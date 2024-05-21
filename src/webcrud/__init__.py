from datetime import date

from fastapi import FastAPI, Form, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.status import HTTP_302_FOUND
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel, Field, ValidationError
from typing import Type, Dict, Any, Optional, Annotated, List, Tuple, Callable, Awaitable, Generator
from dataclasses import dataclass
from enum import StrEnum
import asyncio


from jinja2 import PackageLoader, Environment
j2env = Environment(loader=PackageLoader("webcrud"))



@dataclass
class TableCol:
    content: str
    preformat: bool = False
    element: str = 'td'

@dataclass
class TableColFormater:
    property: str
    format: Optional[str] = None
    preformat: bool = False

class ListTable:
    def __init__(self,
                 model: Type[BaseModel],
                 columns_format: List[TableColFormater]):
        self.model = model
        self.columns_format = columns_format

    def _render_row(self, idx: int, record: BaseModel):
        def format_col(tcf: TableColFormater, row: Dict[str, Any]):
            if tcf.format == None:
                return TableCol(content=str(row[tcf.property]), preformat=tcf.preformat)
            else:
                try:
                    return TableCol(content=tcf.format.format(**row), preformat=tcf.preformat)
                except:
                    return TableCol(content=str(row[tcf.property]), preformat=tcf.preformat)
        
        dr = record.model_dump()
        return [format_col(f, dr) for f in self.columns_format]
    
    def _get_header(self):
        jsch = self.model.model_json_schema()
        for cf in self.columns_format:
            if jsch.get('properties',{}).get(cf.property,{}).get('title'):
                yield jsch['properties'][cf.property]['title']
            else:
                yield cf.property

    def render(self, request: Request, data: List[BaseModel], **ctx) -> str:
        return j2env.get_template("table.html.j2").render(header=self._get_header(),
                                                          rows=[self._render_row(idx, r) for idx,r in enumerate(data)],
                                                          **ctx)
    
    def deploy(self, app, data: List[BaseModel], url_base: str, refresh_seconds: int = None):
        refresh = None if refresh_seconds == None else {'url': url_base, 'secs': refresh_seconds}

        @app.get(url_base)
        async def table_get(request: Request) -> HTMLResponse:
            return HTMLResponse(self.render(request, data, refresh=refresh))
    


@dataclass(kw_only=True)
class StructFormElement:
    id: str
    element: str
    label: Optional[str] = None
    disabled: bool = False
    
@dataclass(kw_only=True)
class StructFormDataElement(StructFormElement):
    name: str
    error: Optional[str] = None
    required: bool = False
    description: Optional[str] = None

@dataclass(kw_only=True)
class StructFormFieldSet(StructFormElement):
    element: str = "fieldset"
    subelements: List[StructFormElement]

@dataclass(kw_only=True)
class StructFormInput(StructFormDataElement):
    input_type: str
    element: str = "input"
    value: Optional[str] = None
    
@dataclass(kw_only=True)
class StructFormInputWithDelButton(StructFormDataElement):
    input_type: str
    element: str = "inputdel"
    value: Optional[str] = None
    url: str
    
@dataclass(kw_only=True)
class StructFormTextarea(StructFormDataElement):
    element: str = "textarea"
    value: Optional[str] = None
    rows: int = 30
    cols: int = 60
    
@dataclass(kw_only=True)
class StructFormButton(StructFormElement):
    url: str
    element: str = "button"
    
@dataclass(kw_only=True)
class StructFormDelButton(StructFormElement):
    url: str
    element: str = "delbutton"

@dataclass
class StructFormSelectOption:
    id: str
    name: str
    value: str
    selected: bool = False

@dataclass(kw_only=True)
class StructFormSwitch(StructFormDataElement):
    value: Optional[str] = None
    element: str = "switch"

@dataclass(kw_only=True)
class StructFormSelect(StructFormDataElement):
    options: List[Tuple[str,str,str]]
    element: str = "select"

class StructForm:
    LIST_DELIMITER = '/'
    def __init__(self,
                 model: Type[BaseModel],
                 return_url: str,
                 numbered_lists: bool = False):

        self.model = model
        self.jsch = self.model.model_json_schema()
        self.numbered_lists = numbered_lists
        self.return_url = return_url

    @staticmethod
    def is_optional(elem):
        if isinstance(elem, list) and len(elem) == 2 and elem[0].get('type') == 'null':
            return elem[1]
        elif isinstance(elem, list) and len(elem) == 2 and elem[1].get('type') == 'null':
            return elem[0]
        else:
            return None

    async def decode_post(self, request: Request) -> Tuple[Optional[BaseModel], Dict[str,Any], Optional[Dict[str,str]]]:
        def gen_list(sdict: Dict):
            try:
                ks = [int(k) for k in sdict]
            except:
                return None
            if not ks:
                return []
            
            mx = max(ks)
            return [(sdict[k] if k in sdict else None) for k in range(0,mx+1)]
        
        def fix_bools():
            for propname,prop in self.jsch.get('properties',{}).items():
                if prop.get('anyOf'):
                    if (optprop := self.is_optional(prop['anyOf'])) != None:
                        if optprop.get("type") == 'boolean':
                            yield propname
                elif prop.get("type") == 'boolean':
                    yield propname
                else:
                    pass
                
        data = {}
        list_keys = set()
        for k,v in (await request.form()).items():
            if self.LIST_DELIMITER in k:
                fn, idx = k.split(self.LIST_DELIMITER)
                if not fn in data:
                    data[fn] = {}
                    list_keys.add(fn)
                data[fn][int(idx)] = v
            else:
                data[k] = v

        for k in list_keys:
            data[k] = gen_list(data[k])
            
        for k in fix_bools():
            if not k in data:
                data[k] = False

        try:
            vdata = self.model.model_validate(data)
            return (vdata, data, None)
        except ValidationError as ve:
            errors = {}
            for e in ve.errors():
                for l in e['loc']:
                    if l in errors:
                        errors[l] += f'\n{e["msg"]}'
                    else:
                        errors[l] = e["msg"]
            return (None, data, errors)


    def gen_elements(self, data: Optional[Dict[str, Any]], errors: Optional[Dict[str, str]], url_base: str) -> Generator[StructFormFieldSet, None, None]:
        def dereference(refstr, obj=None):
            s = refstr.split('/',1)
            if s[0] == '#' or obj == None:
                return dereference(s[1], self.jsch)
            elif len(s) == 1:
                return obj[s[0]]
            else:
                return dereference(s[1], obj[s[0]])


        def gen_select(options={"Yes":True, "No":False}, value=None, **elemparams):
            doptions = [StructFormSelectOption(name=str(k), id=f'{id}_{str(v)}', value=v, selected=(True if str(v) == str(value) else False)) for k,v in options.items()]
            return StructFormSelect(options=doptions, **elemparams)
        
        def gen_typed_field(elem, array_element=False, **elemparams):
            sfi = StructFormInputWithDelButton if array_element else StructFormInput
            if elem.get('enum') != None:
                return gen_select(**elemparams, options={e:e for e in elem['enum']})
            elif elem['type'] == 'string' and elem.get('format') == 'date':
                return sfi(input_type="date", **elemparams)
            elif elem['type'] == 'integer':
                return sfi(input_type="number", **elemparams)
            elif elem['type'] == 'boolean':
                return StructFormSwitch(**elemparams)
            elif elem['type'] == 'string' and elem.get('textarea') == True:
                return StructFormTextarea(**elemparams)
            elif elem['type'] == 'string':
                return sfi(input_type="text", **elemparams)
            else:
                raise NotImplementedError(f'Unsupported element type {elem["type"]} for element {elemparams.get("name")}')
        
        def gen_fields(elemname, elem, schema_required_list, value, error):
            if elem.get('type'):
                required = True if elemname in schema_required_list else False
                disabled = elem.get("disabled", False)
                label = elem.get('title', '')
                descr = elem.get('description')
                
                if elem['type'] == 'array' and elem.get('items'):
                    arrayform = []
                    for idx,ae in enumerate(value if value else []):
                        eid = f"{elemname}{self.LIST_DELIMITER}{idx}"
                        ename = f"{elemname}{self.LIST_DELIMITER}{idx}"
                        arrayform.append(gen_typed_field(elem['items'], name=ename, id=eid,
                                                         label=(f'{idx}' if self.numbered_lists else None),
                                                         description=None, required=False, value=ae,
                                                         error=None, disabled=False,
                                                         url=f'{url_base}/{elemname}/del/{idx}', array_element=True))
                    arrayform.append(StructFormButton(id=f'{elemname}_plus', label="+", url=f'{url_base}/{elemname}/add'))
                    yield StructFormFieldSet(id=elemname, label=label, subelements=arrayform, disabled=disabled)
                else:
                    yield gen_typed_field(elem, id=elemname, name=elemname, label=label, description=descr,
                                          required=required, value=value, error=error, disabled=disabled)
            else:
                raise NotImplementedError(f'Unsupported element {elemname} : {elem}')


        fields = []
        for propname,prop in self.jsch.get('properties',{}).items():
            error = errors.get(propname) if errors else None
            value = data.get(propname) if data else prop['default'] if 'default' in prop else None

            if prop.get('anyOf'): # Optional[] case
                if (optprop := self.is_optional(prop['anyOf'])) != None:
                    rprop = prop.copy()
                    rprop.pop('anyOf')
                    rprop |= optprop
                    for e in gen_fields(propname, rprop, [], value, error):
                        fields.append(e)
                else:
                    raise RuntimeError(f'Unsupported nested element {propname} : {prop}')
            elif prop.get('allOf'): # enum case
                if len(prop['allOf']) == 1:
                    cprop = prop['allOf'][0]
                    if cprop.get('$ref'):
                        cprop = dereference(cprop.get('$ref'))
                        for e in gen_fields(propname, cprop, self.jsch.get('required', []), value, error):
                            fields.append(e)
                        
                else:
                    raise RuntimeError(f'Unsupported nested element {propname} : {prop}')
            else:
                for e in gen_fields(propname, prop, self.jsch.get('required', []), value, error):
                    fields.append(e)

        yield StructFormFieldSet(id=self.jsch.get('title').lower(), label=self.jsch.get('title'), subelements=fields)

    
    def render(self, data: Optional[Dict[str, Any]], errors: Optional[Dict[str, str]], url_base: str):
        fes = list(self.gen_elements(data, errors, url_base))
        return j2env.get_template("form.html.j2").render(form_elements=fes, form_submit_url=url_base, form_return_url=self.return_url)


class ListStructForm(StructForm):
    def deploy(self, app, data: List[BaseModel], url_base: str):
        @app.get(f'{url_base}/'+'{idx}')
        async def form_get(request: Request, idx: int):
            ddata = data[idx].model_dump() if idx >= 0 and len(data) > idx else {}
            return HTMLResponse(self.render(ddata, None, f'{url_base}/{idx}'))
        
        @app.post(f'{url_base}/'+'{idx}')
        async def form_submit(request: Request, idx: int) -> HTMLResponse:
            element, rawdata, errors = await self.decode_post(request)
            if element:
                if idx >= len(data):
                    data.append(element)
                else:
                    data[idx] = element

                return RedirectResponse(self.return_url, status_code=HTTP_302_FOUND)
            else:
                return HTMLResponse(self.render(rawdata, errors, f'{url_base}/{idx}'))

        @app.post(f'{url_base}/'+'{idx}/{listname}/del/{lidx}')
        async def form_post_list_del(request: Request, idx: int, listname: str, lidx: int):
            element, rawdata, errors = await self.decode_post(request)
            rawdata[listname].pop(lidx)
            return HTMLResponse(self.render(rawdata, None, f'{url_base}/{idx}'))
        
        @app.post(f'{url_base}/'+'{idx}/{listname}/add')
        async def form_post_list_add(request: Request, idx: int, listname: str):
            element, rawdata, errors = await self.decode_post(request)
            if not listname in rawdata:
                rawdata[listname] = []
            rawdata[listname].append(None)
            return HTMLResponse(self.render(rawdata, None, f'{url_base}/{idx}'))
        

class CRUDListTable(ListTable):
    def _render_row(self, idx: int, record: BaseModel, url_base: str):
        return super()._render_row(idx, record) + [
            StructFormButton(id=f'tab_edit_{idx}', label='Edit', url=f'{url_base}/edit/{idx}'),
            StructFormDelButton(id=f'tab_edit_{idx}', label='Delete', url=f'{url_base}/del/{idx}')]
        
    def render(self, request: Request, data: List[BaseModel], url_base: str) -> str:
        return j2env.get_template("table.html.j2").render(header=list(self._get_header())+['', ''],
                                                          rows=[self._render_row(idx, r, url_base) for idx,r in enumerate(data)],
                                                          extra=StructFormButton(id='tab_add', label='+',
                                                                                 url=f'{url_base}/edit/{len(data)}'))

    def deploy(self, app, data: List[BaseModel], url_base: str):
        @app.get(url_base)
        async def table_get(request: Request) -> HTMLResponse:
            return HTMLResponse(self.render(request, data, url_base))
        
        @app.get(f'{url_base}/del/'+'{idx}')
        async def table_del(request: Request, idx: int) -> HTMLResponse:
            data.pop(idx)
            return HTMLResponse(self.render(request, data, url_base))
        
        edit_form = ListStructForm(self.model, return_url=url_base)
        edit_form.deploy(app, data, f'{url_base}/edit')

@dataclass(kw_only=True)
class SSEUpdate:
    event: str
    data: str
    retry: int = 5000

    def send(self):
        return { "event": self.event, "retry": self.retry, "data": self.data }

class SSEBroadcast:
    def __init__(self):
        self.slots = []
        
    async def send(self, sseupdate: SSEUpdate):
        for s in self.slots:
            await s.put(sseupdate)

    async def _ep_evgen(self, request: Request):
        q = asyncio.Queue()
        qidx = len(self.slots)
        self.slots.append(q)
        while True:
            update = await q.get()
            if await request.is_disconnected():
                break
            yield update.send()
        self.slots.pop(qidx)

    def deploy(self, app, urlbase: str):
        @app.get(urlbase)
        async def get_event_endpoint(request: Request):
            return EventSourceResponse(self._ep_evgen(request))




# Test code
def tests(*_):
    class Attitude(StrEnum):
        criminal = "Criminal"
        hacker = "Hacker"
        overachiever = "Overachiever"
        atlevel = "atLevel"
        lazy = "Lazy"
        stupid = "Stupid"
        dork = "Dork"

    class User(BaseModel):
        id: int = Field(json_schema_extra={"disabled": True}, default=10)
        name: str = Field(title="NAME", pattern='^[A-Z][a-z]+', preformat=True)
        dob: date = Field(title='Date of Birth')
        geek: bool = False
        cars: List[str] = Field(title='List of Cars', default=[])
        bio: Optional[str] = Field(title="Biography", description="This is a looong description.", json_schema_extra={"textarea": True}, default=None)
        attitude: Attitude = Attitude.hacker

    users = [
        User(id=1, name='John', dob=date(1990, 1, 1), cars=['Dacia', 'BMW', 'Audi']),
        User(id=2, name='Jack', dob=date(1991, 1, 1)),
        User(id=3, name='Jill', dob=date(1992, 1, 1)),
        User(id=4, name='Jane', dob=date(1993, 1, 1)),
    ]

    class NumRecord(BaseModel):
        x: int
        y: int
        z: int

    nums = []
    ssetable = SSEBroadcast()
    rtable = ListTable(NumRecord, [TableColFormater('x'), TableColFormater('y'), TableColFormater('z')])

    async def send_updates():
        while True:
            try:
                await ssetable.send(SSEUpdate(event="rtab", data=rtable.render(None, nums)))
            except Exception as e:
                print(e)
            await asyncio.sleep(5)

    async def periodic_update():
        j = 1
        while True:
            for i in range(10):
                n = NumRecord(x=j*(1+i)-11, y=j+i*7-140, z=j*2-i+3)
                if i < len(nums):
                    nums[i] = n
                else:
                    nums.append(n)
            j += 1
            await asyncio.sleep(5)
    
    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        dgen = asyncio.create_task(periodic_update())
        ups = asyncio.create_task(send_updates())
        yield
        dgen.cancel()
        ups.cancel()
        try:
            await dgen
            await ups
        except:
            pass

    app = FastAPI(lifespan=lifespan)
    
    import pprint
    #pprint.pprint(User.model_json_schema())

    @app.get('/')
    async def get_landing() -> HTMLResponse:
        return HTMLResponse(j2env.get_template("testpage.html.j2").render())
    
    @app.post('/login/password')
    async def login(request: Request) -> HTMLResponse:
        pprint.pprint(await request.form())
        return await get_landing()

    utable = CRUDListTable(User, [TableColFormater('id'), TableColFormater('name'), TableColFormater('geek')])
    utable.deploy(app, users, '/users')

    rtable.deploy(app, nums, '/rtable', refresh_seconds=10)
    ssetable.deploy(app, '/ssetabupdate')

    @app.get('/ssetab')
    async def get_ssetab(request: Request) -> HTMLResponse:
        return HTMLResponse(j2env.get_template("sse.html.j2").render(sse_url='/ssetabupdate'))

    return app

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(tests(), host="127.0.0.1", port=8000, log_level="debug")
