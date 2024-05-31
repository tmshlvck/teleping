# coding: utf-8
"""
Telephant Ping WebUI

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
from typing import Optional, List, Dict, Any
import uvicorn
from prometheus_client import make_asgi_app

from webcrud import ListTable, TableColFormatter

from teleping.config import NormalizedTarget, Config

from fastapi import FastAPI
from contextlib import asynccontextmanager
import asyncio
import logging
import time
import datetime


class HostData(BaseModel):
    host: str
    ip: str
    last_rx_time: float
    total_tx_ping: int
    total_rx_ping_ok: int
    total_rx_ping_corrupt: int
    total_rx_pong_ok: int
    total_rx_pong_corrupt: int
    total_rx_malformed: int
    total_lost: int
    rtt_avg_15s: float
    loss_rate_15s: float
    rtt_avg_60s: float
    loss_rate_60s: float
    rtt_avg_300s: float
    loss_rate_300s: float

def hostdata_row_classifier(d: HostData) -> str:
    if d.loss_rate_15s > 0.5 or d.loss_rate_60s > 0.5 or d.loss_rate_300s > 0.5:
        return ListTable.ROW_CLASS_DANGER
    if d.loss_rate_15s > 0.1 or d.loss_rate_60s > 0.1 or d.loss_rate_300s > 0.1 or d.rtt_avg_15s > 600 or d.rtt_avg_60s > 600 or d.rtt_avg_300s > 600:
        return ListTable.ROW_CLASS_WARNING


def gen_webui(tc: Any, title: str):
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
        tc.shutdown()

    app = FastAPI(lifespan=lifespan)
    j2t = Jinja2Templates(env=Environment(loader=PackageLoader("teleping")))

    ttable = ListTable(HostData, [TableColFormatter('host'), TableColFormatter('ip', preformat=True), TableColFormatter('total_tx_ping'),
                                  TableColFormatter("total_rx_pong_ok"), TableColFormatter('total_rx_malformed'),
                                  TableColFormatter("total_rx_ping_ok"), TableColFormatter("rtt_avg_15s", format="{rtt_avg_15s:.1f}"),
                                  TableColFormatter("loss_rate_15s", formatter=lambda d: f"{(100*d.loss_rate_15s):.1f}%"), ], row_classifier=hostdata_row_classifier)

    async def get_hostdata() -> Dict[str,HostData]:
        hmet = await asyncio.to_thread(tc.udpping.get_hostmetrics, True)
        return {h : HostData(**hmet[h]) for h in hmet}

    async def get_udptable_rows() -> List[HostData]:
        return sorted(list((await get_hostdata()).values()), key=lambda d: d.host)

    async def event_generator(request: Request):
        def ev(name: str, data: str):
          return { "event": name, "retry": 5000, "data": data }
        
        while True:
            if await request.is_disconnected():
                break
            yield ev("udptable", ttable.render(request, list(await get_udptable_rows())))           
            await asyncio.sleep(1.0)  # in seconds

    @app.get("/udptable_updates")
    async def runStatus(request: Request):
        return EventSourceResponse(event_generator(request))

    @app.get('/')
    async def html_landing(request: Request) -> HTMLResponse:
        return j2t.TemplateResponse(request=request, name="udpping.html.j2", context={})
    
    #@app.get('/table')
    #async def html_landing(request: Request) -> HTMLResponse:
    #    return HTMLResponse(ttable.render(request, list(await get_udptable_rows())))
    
    @app.get('/reconfig')
    async def html_reconfig(request: Request) -> HTMLResponse:
        await asyncio.to_thread(tc.reconfig)
        return j2t.TemplateResponse(request=request, name="message.html.j2", context={"status": "OK", "message": f"Reconfigured at {datetime.datetime.now()}.", "timestamp": str(time.time())})
    
    @app.get('/api/v1/stats')
    async def api_stats(request: Request) -> Dict[str,HostData]:
        return await get_hostdata()
    
    @app.get('/api/v1/reconfig')
    async def api_reconfig(request: Request) -> Dict[str,str]:
        await asyncio.to_thread(tc.reconfig)
        return {"status": "OK", "timestamp": str(time.time())}

    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    return app


def start_webui(tc: Any):
    uvicorn.run(gen_webui(tc, 'Telephant Ping'), host=tc.cfg.control.listen, port=tc.cfg.control.port, log_level="debug" if tc.cfg.debug else "info")
