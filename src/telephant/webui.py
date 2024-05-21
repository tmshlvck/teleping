# coding: utf-8
"""
Telephant WebUI

Copyright (C) 2024 Tomas Hlavacek (tmshlvck@gmail.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""


from fastapi import FastAPI, Form, Depends, Request
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse
from fastapi.templating import Jinja2Templates
from jinja2 import PackageLoader, Environment
from pydantic import BaseModel
from typing import Optional, Dict
import uvicorn
from prometheus_client import make_asgi_app

from webcrud import ListTable, TableColFormater

from telephant.config import NormalizedTarget, Config
from telephant.common import TelephantCore
from telephant.udpping import PeerStats

from fastapi import FastAPI
from contextlib import asynccontextmanager
import asyncio
import logging


class UdpTableRow(BaseModel):
    host: str
    total_tx_ping: int
    total_rx_pong_ok: int
    total_rx_malformed: int
    total_rx_ping_ok: int
    rtt_avg15s_ms: Optional[float]


def gen_webui(tc: TelephantCore, title: str):
    async def periodic_update(): 
        while True:
            await asyncio.sleep(5)
            
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        put=asyncio.create_task(periodic_update())
        yield
        put.cancel()
        try:
            await put
        except:
            pass
        logging.info('Shutting down FastAPI lifespan')

    app = FastAPI(lifespan=lifespan)
    j2t = Jinja2Templates(env=Environment(loader=PackageLoader("telephant")))

    ttable = ListTable(UdpTableRow, [TableColFormater('host'), TableColFormater('total_tx_ping'),
                                          TableColFormater("total_rx_pong_ok"), TableColFormater('total_rx_malformed'),
                                          TableColFormater("total_rx_ping_ok"), TableColFormater("rtt_avg15s_ms", format="{rtt_avg15s_ms:.2f}"),])

    async def get_udptable_rows():
        stats = await asyncio.to_thread(tc.udpping.get_stats)
        tgts_by_addr = tc.cfg.normalized_targets_by_ip
        for tip in stats:
            if tip in tgts_by_addr and tgts_by_addr[tip].name:
                host = f'{tgts_by_addr[tip].name} ({tip})'
            elif tgts_by_addr[tip].host:
                host = f'{tgts_by_addr[tip].host} ({tip})'
            else:
                host = tip
            yield UdpTableRow(host=host, total_tx_ping=stats[tip].total_tx_ping, total_rx_pong_ok=stats[tip].total_rx_pong_ok,
                                  total_rx_malformed=stats[tip].total_rx_malformed, total_rx_ping_ok=stats[tip].total_rx_ping_ok,
                                  rtt_avg15s_ms=stats[tip].rtt_avg15s_ms)

    async def event_generator(request: Request):
        def ev(name: str, data: str):
          return { "event": name, "retry": 5000, "data": data }
        
        while True:
            if await request.is_disconnected():
                break
            
            #if True:
            #  yield ev("alert", f'<div class="alert alert-primary" role="alert" id="alert">A simple primary alert {i}!</div>')
      
            yield ev("udptable", ttable.render(request, [r async for r in get_udptable_rows()]))
            
            await asyncio.sleep(1.0)  # in seconds

    @app.get("/udptable_updates")
    async def runStatus(request: Request):
        return EventSourceResponse(event_generator(request))

    @app.get('/')
    async def html_landing(request: Request) -> HTMLResponse:
        return j2t.TemplateResponse(request=request, name="udpping.html.j2", context={})
    
    @app.get('/api/v1/stats')
    async def api_stats(request: Request) -> Dict[str,PeerStats]:
        return await asyncio.to_thread(tc.udpping.get_peerstats_dict)

    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    return app


def start_webui(tc: TelephantCore):
    uvicorn.run(gen_webui(tc, 'Telephant'), host=tc.cfg.control.listen, port=tc.cfg.control.port, log_level="debug" if tc.cfg.debug else "info")
