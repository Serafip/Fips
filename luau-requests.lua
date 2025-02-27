local __DARKLUA_BUNDLE_MODULES __DARKLUA_BUNDLE_MODULES={cache={},load=function(
m)if not __DARKLUA_BUNDLE_MODULES.cache[m]then __DARKLUA_BUNDLE_MODULES.cache[m]
={c=__DARKLUA_BUNDLE_MODULES[m]()}end return __DARKLUA_BUNDLE_MODULES.cache[m].c
end}do function __DARKLUA_BUNDLE_MODULES.a()local Set={}Set.mt={__index=Set}
function Set:new(values)local instance={}local isSet if getmetatable(values)==
Set.mt then isSet=true end if type(values)=='table'then if not isSet and#values>
0 then for _,v in ipairs(values)do instance[v]=true end else for k in pairs(
values)do instance[k]=true end end elseif values~=nil then instance={[values]=
true}end return setmetatable(instance,Set.mt)end function Set:add(e)if e~=nil
then self[e]=true end return self end function Set:remove(e)if e~=nil then self[
e]=nil end return self end function Set:tolist()local res={}for k in pairs(self)
do table.insert(res,k)end return res end Set.to_list=Set.tolist Set.mt.__add=
function(a,b)local res,a,b=Set:new(),Set:new(a),Set:new(b)for k in pairs(a)do
res[k]=true end for k in pairs(b)do res[k]=true end return res end Set.mt.__sub=
function(a,b)local res,a,b=Set:new(),Set:new(a),Set:new(b)for k in pairs(a)do
res[k]=true end for k in pairs(b)do res[k]=nil end return res end Set.mt.__mul=
function(a,b)local res,a,b=Set:new(),Set:new(a),Set:new(b)for k in pairs(a)do
res[k]=b[k]end return res end Set.mt.__tostring=function(set)local s='{'local
sep=''for k in pairs(set)do s=s..sep..tostring(k)sep=', 'end return s..'}'end
local ElementNode={}ElementNode.mt={__index=ElementNode}function ElementNode:new
(index,nameortext,node,descend,openstart,openend)local instance={index=index,
name=nameortext,level=0,parent=nil,root=nil,nodes={},_openstart=openstart,
_openend=openend,_closestart=openstart,_closeend=openend,attributes={},id=nil,
classes={},deepernodes=Set:new(),deeperelements={},deeperattributes={},deeperids
={},deeperclasses={}}instance.attrs=instance.attributes instance.children=
instance.nodes instance.descendants=instance.deepernodes instance.
descendant_elements=instance.deeperelements instance.descendant_attrs=instance.
deeperattributes instance.descendent_ids=instance.deeperids instance.
descendant_classes=instance.deeperclasses if not node then instance.name='root'
instance.root=instance instance._text=nameortext local length=string.len(
nameortext)instance._openstart,instance._openend=1,length instance._closestart,
instance._closeend=1,length elseif descend then instance.root=node.root instance
.parent=node instance.level=node.level+1 table.insert(node.nodes,instance)else
instance.root=node.root instance.parent=node.parent or node instance.level=node.
level table.insert((node.parent and node.parent.nodes or node.nodes),instance)
end return setmetatable(instance,ElementNode.mt)end function ElementNode:text()
return string.sub(self.root._text,self._openstart,self._closeend)end ElementNode
.gettext=ElementNode.text function ElementNode:settext(c)self.root._text=c end
function ElementNode:textonly()return(self:text():gsub('<[^>]*>',''))end
function ElementNode:content()return string.sub(self.root._text,self._openend+1,
self._closestart-1)end ElementNode.getcontent=ElementNode.content function
ElementNode:addattribute(k,v)self.attributes[k]=v if string.lower(k)=='id'then
self.id=v elseif string.lower(k)=='class'then for class in string.gmatch(v,'%S+'
)do table.insert(self.classes,class)end end end function ElementNode:links()
local r={}for _,anchor in ipairs(self:select('a[href]'))do if#anchor.attributes.
href>0 then table.insert(r,anchor.attributes.href)end end return r end function
ElementNode:absolutelinks(page_url)page_url=page_url or self.page_url or''
page_url=page_url:split('?')[1]:split('#')[1]local domain=page_url:split('://')
domain=domain[#domain]domain=domain:split('/')[1]local protocol=page_url:find(
'://')and page_url:split('://')[1]or'http'while page_url:sub(-1,-1)=='/'do
page_url=page_url:sub(1,-2)end local r={}for _,anchor in ipairs(self:select(
'a[href]'))do if#anchor.attributes.href>0 then local link=anchor.attributes.href
if not link:find('://')then if link:sub(1,2)=='//'then link=protocol..':'..link
elseif link:sub(1,1)=='/'then link=protocol..'://'..domain..link else link=
page_url..'/'..link end end table.insert(r,link)end end return r end ElementNode
.absolute_links=ElementNode.absolutelinks local function insert(table,name,node)
table[name]=table[name]or Set:new()table[name]:add(node)end function ElementNode
:close(closestart,closeend)if closestart and closeend then self._closestart,self
._closeend=closestart,closeend end local node=self while true do node=node.
parent if not node then break end node.deepernodes:add(self)insert(node.
deeperelements,self.name,self)for k in pairs(self.attributes)do insert(node.
deeperattributes,k,self)end if self.id then insert(node.deeperids,self.id,self)
end for _,v in ipairs(self.classes)do insert(node.deeperclasses,v,self)end end
end local function escape(s)return string.gsub(s,'([%^%$%(%)%%%.%[%]%*%+%-%?])',
'%%%1')end local function select(self,s)if not s or type(s)~='string'or s==''
then return Set:new()end local sets={['']=self.deeperelements,['[']=self.
deeperattributes,['#']=self.deeperids,['.']=self.deeperclasses}local function
match(t,w)local m,e,v if t=='['then w,m,e,v=string.match(w,
'([^=|%*~%$!%^]+)([|%*~%$!%^]?)(=?)(.*)')end local matched=Set:new(sets[t][w])if
e=='='then if#v<2 then v="'"..v.."'"end v=string.sub(v,2,#v-1)if m=='!'then
matched=Set:new(self.deepernodes)end for node in pairs(matched)do local a=node.
attributes[w]if m==''and a~=v then matched:remove(node)elseif m=='!'and a==v
then matched:remove(node)elseif m=='|'and string.match(a,'^[^-]*')~=v then
matched:remove(node)elseif m=='*'and string.match(a,escape(v))~=v then matched:
remove(node)elseif m=='~'then matched:remove(node)for word in string.gmatch(a,
'%S+')do if word==v then matched:add(node)break end end elseif m=='^'and string.
match(a,'^'..escape(v))~=v then matched:remove(node)elseif m=='$'and string.
match(a,escape(v)..'$')~=v then matched:remove(node)end end end return matched
end local subjects,resultset,childrenonly=Set:new({self})for part in string.
gmatch(s,'%S+')do repeat if part=='>'then childrenonly=true break end resultset=
Set:new()for subject in pairs(subjects)do local star=subject.deepernodes if
childrenonly then star=Set:new(subject.nodes)end resultset=resultset+star end
childrenonly=false if part=='*'then break end local excludes,filter=Set:new()
local start,pos=0,0 while true do local switch,stype,name,eq,quote start,pos,
switch,stype,name,eq,quote=string.find(part,
'(%(?%)?)([:%[#.]?)([%w-_\\]+)([|%*~%$!%^]?=?)([\'"]?)',pos+1)if not name then
break end repeat if':'==stype then filter=name break end if')'==switch then
filter=nil end if'['==stype and''~=quote then local value start,pos,value=string
.find(part,'(%b'..quote..quote..')]',pos)name=name..eq..value end local matched=
match(stype,name)if filter=='not'then excludes=excludes+matched else resultset=
resultset*matched end break until true end resultset=resultset-excludes subjects
=Set:new(resultset)break until true end resultset=resultset:tolist()table.sort(
resultset,function(a,b)return a.index<b.index end)return resultset end function
ElementNode:select(s)return select(self,s)end ElementNode.mt.__call=select
return ElementNode end function __DARKLUA_BUNDLE_MODULES.b()return{area=true,
base=true,br=true,col=true,command=true,embed=true,hr=true,img=true,input=true,
keygen=true,link=true,meta=true,param=true,source=true,track=true,wbr=true}end
function __DARKLUA_BUNDLE_MODULES.c()local function rine(val)return(val and#val>
0)and val end local function rit(a)return(type(a)=='table')and a end
local function dont_crash()if math.random()<=0.004 then wait()end return true
end local noop=function()end local esc=function(s)return string.gsub(s,
'([%^%$%(%)%%%.%[%]%*%+%-%?])','%%%1')end local str=tostring local char=string.
char local opts={}local prn=opts.silent and noop or function(l,f,...)local fd=(l
=='i')and'stdout'or'stderr'local t=(' [%s] '):format(l:upper())print(
'[HTMLParser]'..t..f:format(...)..(opts.nonl or'\n'))end local err=opts.noerr
and noop or function(f,...)prn('e',f,...)end local out=opts.noout and noop or
function(f,...)prn('i',f,...)end local line=noop local dbg=opts.debug and
function(f,...)prn('d',f:gsub('#LINE#',str(line(3))),...)end or noop local
ElementNode=__DARKLUA_BUNDLE_MODULES.load('a')local voidelements=
__DARKLUA_BUNDLE_MODULES.load('b')local HtmlParser={}local function parse(text,
limit,page_url)local opts=rine(opts)or{}or{}opts.looplimit=opts.looplimit or
100000000 local text=str(text)local limit=limit or opts.looplimit or 100000000
local tpl=false if not opts.keep_comments then text=text:gsub('<!%-%-.-%-%->',''
)end local tpr={}if not opts.keep_danger_placeholders then local busy,i={},0
repeat local cc=char(i)if not(text:match(cc))then if not(tpr['<'])or not(tpr['>'
])then if not(busy[i])then if not(tpr['<'])then tpr['<']=cc elseif not(tpr['>'])
then tpr['>']=cc end busy[i]=true dbg('c:{%s}||cc:{%d}||tpr[c]:{%s}',str(c),cc:
byte(),str(tpr[c]))dbg('busy[i]:{%s},i:{%d}',str(busy[i]),i)dbg(
'[FindPH]:#LINE# Success! || i=%d',i)else dbg('[FindPH]:#LINE# Busy! || i=%d',i)
end dbg('c:{%s}||cc:{%d}||tpr[c]:{%s}',c,cc:byte(),str(tpr[c]))dbg('%s',str(busy
[i]))else dbg('[FindPH]:#LINE# Done!',i)break end else dbg(
'[FindPH]:#LINE# Text contains this byte! || i=%d',i)end local skip=1 if i==31
then skip=96 end i=i+skip until(i==255)i=nil if not(tpr['<'])or not(tpr['>'])
then err(
[[Impossible to find at least two unused byte codes in this HTML-code. We need it to escape bracket-contained placeholders inside tags.]]
)err(
[[Consider enabling 'keep_danger_placeholders' option (to silence this error, if parser wasn't failed with current HTML-code) or manually replace few random bytes, to free up the codes.]]
)else dbg("[FindPH]:#LINE# Found! || '<'=%d, '>'=%d",tpr['<']:byte(),tpr['>']:
byte())end local function g(id,...)local arg={...}local orig=arg[id]arg[id]=arg[
id]:gsub('(.)',tpr)if arg[id]~=orig then tpl=true dbg('[g]:#LINE# orig: %s',str(
orig))dbg('[g]:#LINE# replaced: %s',str(arg[id]))end dbg(
'[g]:#LINE# called, id: %s, arg[id]: %s, args { '..(('{%s}, '):rep(#arg):gsub(
', $',''))..' }',id,arg[id],...)dbg('[g]:#LINE# concat(arg): %s',table.concat(
arg))return table.concat(arg)end text=text:gsub("(=[%s]-)(%b'')",function(...)
return g(2,...)end):gsub('(=[%s]-)(%b"")',function(...)return g(2,...)end):gsub(
'(<'..(opts.tpl_skip_pattern or'[^!]')..')([^>]+)(>)',function(...)return g(2,
...)end):gsub('('..(tpr['<']or'__FAILED__')..')('..(opts.tpl_marker_pattern or
'[^%w%s]')..')([%g%s]-)(%2)(>)([^>]*>)',function(...)return g(5,...)end)end
local index=0 local root=ElementNode:new(index,str(text))root.page_url=page_url
local node,descend,tpos,opentags=root,true,1,{}while dont_crash()do if index==
limit then err(
[[Main loop reached loop limit (%d). Consider either increasing it or checking HTML-code for syntax errors]]
,limit)break end local openstart,name openstart,tpos,name=root._text:find(
'<([%w-]+)[^>]*>',tpos)dbg(
'[MainLoop]:#LINE# openstart=%s || tpos=%s || name=%s',str(openstart),str(tpos),
str(name))if not name then break end index=index+1 local tag=ElementNode:new(
index,str(name),(node or{}),descend,openstart,tpos)tag.page_url=page_url node=
tag local tagloop local tagst,apos=tag:gettext(),1 while dont_crash()do if
tagloop==limit then err(
[[Tag parsing loop reached loop limit (%d). Consider either increasing it or checking HTML-code for syntax errors]]
,limit)break end local start,k,eq,quote,v,zsp start,apos,k,zsp,eq,zsp,quote=
tagst:find('%s+([^%s=/>]+)([%s]-)(=?)([%s]-)([\'"]?)',apos)dbg(
[=[[TagLoop]:#LINE# start=%s || apos=%s || k=%s || zsp='%s' || eq='%s', quote=[%s]]=]
,str(start),str(apos),str(k),str(zsp),str(eq),str(quote))if not k or k=='/>'or k
=='>'then break end if eq=='='then local pattern='=([^%s>]*)'if quote~=''then
pattern=quote..'([^'..quote..']*)'..quote end start,apos,v=tagst:find(pattern,
apos)dbg('[TagLoop]:#LINE# start=%s || apos=%s || v=%s || pattern=%s',str(start)
,str(apos),str(v),str(pattern))end v=v or''if tpl then for rk,rv in pairs(tpr)do
v=v:gsub(rv,rk)dbg('[TagLoop]:#LINE# rv=%s || rk=%s',str(rv),str(rk))end end
dbg('[TagLoop]:#LINE# k=%s || v=%s',str(k),str(v))tag:addattribute(k,v)tagloop=(
tagloop or 0)+1 end if voidelements[tag.name:lower()]then descend=false tag:
close()else opentags[tag.name]=opentags[tag.name]or{}table.insert(opentags[tag.
name],tag)end local closeend=tpos local closingloop while dont_crash()do if
closingloop==limit then err(
[[Tag closing loop reached loop limit (%d). Consider either increasing it or checking HTML-code for syntax errors]]
,limit)break end local closestart,closing,closename closestart,closeend,closing,
closename=root._text:find('[^<]*<(/?)([%w-]+)',closeend)dbg(
[[[TagCloseLoop]:#LINE# closestart=%s || closeend=%s || closing=%s || closename=%s]]
,str(closestart),str(closeend),str(closing),str(closename))if not closing or
closing==''then break end tag=table.remove(opentags[closename]or{})or tag
closestart=root._text:find('<',closestart)dbg(
'[TagCloseLoop]:#LINE# closestart=%s',str(closestart))tag:close(closestart,
closeend+1)node=tag.parent descend=true closingloop=(closingloop or 0)+1 end end
if tpl then dbg('tpl')for k,v in pairs(tpr)do root._text=root._text:gsub(v,k)end
end return root end HtmlParser.parse=parse return HtmlParser end function
__DARKLUA_BUNDLE_MODULES.d()local M={}M.version='0.9.0'M.options={separator='&'}
M.services={acap=674,cap=1026,dict=2628,ftp=21,gopher=70,http=80,https=443,iax=
4569,icap=1344,imap=143,ipp=631,ldap=389,mtqp=1038,mupdate=3905,news=2009,nfs=
2049,nntp=119,rtsp=554,sip=5060,snmp=161,telnet=23,tftp=69,vemmi=575,afs=1483,
jms=5673,rsync=873,prospero=191,videotex=516}local legal={['-']=true,['_']=true,
['.']=true,['!']=true,['~']=true,['*']=true,["'"]=true,['(']=true,[')']=true,[
':']=true,['@']=true,['&']=true,['=']=true,['+']=true,['$']=true,[',']=true,[';'
]=true}local function decode(str,path)local str=str if not path then str=str:
gsub('+',' ')end return(str:gsub('%%(%x%x)',function(c)return string.char(
tonumber(c,16))end))end local function encode(str)return(str:gsub(
'([^A-Za-z0-9%_%.%-%~])',function(v)return string.upper(string.format('%%%02x',
string.byte(v)))end))end local function encodeValue(str)local str=encode(str)
return str:gsub('%%20','+')end local function encodeSegment(s)local legalEncode=
function(c)if legal[c]then return c end return encode(c)end return s:gsub(
'([^a-zA-Z0-9])',legalEncode)end local function concat(s,u)return s..u:build()
end function M:build()local url=''if self.path then local path=self.path path:
gsub('([^/]+)',function(s)return encodeSegment(s)end)url=url..tostring(path)end
if self.query then local qstring=tostring(self.query)if qstring~=''then url=url
..'?'..qstring end end if self.host then local authority=self.host if self.port
and self.scheme and M.services[self.scheme]~=self.port then authority=authority
..':'..self.port end local userinfo if self.user and self.user~=''then userinfo=
self.user if self.password then userinfo=userinfo..':'..self.password end end if
userinfo and userinfo~=''then authority=userinfo..'@'..authority end if
authority then if url~=''then url='//'..authority..'/'..url:gsub('^/+','')else
url='//'..authority end end end if self.scheme then url=self.scheme..':'..url
end if self.fragment then url=url..'#'..self.fragment end return url end
function M.buildQuery(tab,sep,key)local query={}if not sep then sep=M.options.
separator or'&'end local keys={}for k in pairs(tab)do keys[#keys+1]=k end table.
sort(keys)for _,name in ipairs(keys)do local value=tab[name]name=encode(
tostring(name))if key then name=string.format('%s[%s]',tostring(key),tostring(
name))end if type(value)=='table'then query[#query+1]=M.buildQuery(value,sep,
name)else local value=encodeValue(tostring(value))if value~=''then query[#query+
1]=string.format('%s=%s',name,value)else query[#query+1]=name end end end return
table.concat(query,sep)end function M.parseQuery(str,sep)if not sep then sep=M.
options.separator or'&'end local values={}for key,val in str:gmatch(string.
format('([^%q=]+)(=*[^%q=]*)',sep,sep))do local key=decode(key)local keys={}key=
key:gsub('%[([^%]]*)%]',function(v)if string.find(v,'^-?%d+$')then v=tonumber(v)
else v=decode(v)end table.insert(keys,v)return'='end)key=key:gsub('=+.*$','')key
=key:gsub('%s','_')val=val:gsub('^=+','')if not values[key]then values[key]={}
end if#keys>0 and type(values[key])~='table'then values[key]={}elseif#keys==0
and type(values[key])=='table'then values[key]=decode(val)end local t=values[key
]for i,k in ipairs(keys)do if type(t)~='table'then t={}end if k==''then k=#t+1
end if not t[k]then t[k]={}end if i==#keys then t[k]=decode(val)end t=t[k]end
end setmetatable(values,{__tostring=M.buildQuery})return values end function M:
setQuery(query)local query=query if type(query)=='table'then query=M.buildQuery(
query)end self.query=M.parseQuery(query)return query end function M:setAuthority
(authority)self.authority=authority self.port=nil self.host=nil self.userinfo=
nil self.user=nil self.password=nil authority=authority:gsub('^([^@]*)@',
function(v)self.userinfo=v return''end)authority=authority:gsub('^%[[^%]]+%]',
function(v)self.host=v return''end)authority=authority:gsub(':([^:]*)$',function
(v)self.port=tonumber(v)return''end)if authority~=''and not self.host then self.
host=authority:lower()end if self.userinfo then local userinfo=self.userinfo
userinfo=userinfo:gsub(':([^:]*)$',function(v)self.password=v return''end)self.
user=userinfo end return authority end function M.parse(url)local comp={}M.
setAuthority(comp,'')M.setQuery(comp,'')local url=tostring(url or'')url=url:
gsub('#(.*)$',function(v)comp.fragment=v return''end)url=url:gsub(
'^([%w][%w%+%-%.]*)%:',function(v)comp.scheme=v:lower()return''end)url=url:gsub(
'%?(.*)',function(v)M.setQuery(comp,v)return''end)url=url:gsub('^//([^/]*)',
function(v)M.setAuthority(comp,v)return''end)comp.path=decode(url,true)
setmetatable(comp,{__index=M,__concat=concat,__tostring=M.build})return comp end
function M.removeDotSegments(path)local fields={}if string.len(path)==0 then
return''end local startslash=false local endslash=false if string.sub(path,1,1)
=='/'then startslash=true end if(string.len(path)>1 or startslash==false)and
string.sub(path,-1)=='/'then endslash=true end path:gsub('[^/]+',function(c)
table.insert(fields,c)end)local new={}local j=0 for i,c in ipairs(fields)do if c
=='..'then if j>0 then j=j-1 end elseif c~='.'then j=j+1 new[j]=c end end local
ret=''if#new>0 and j>0 then ret=table.concat(new,'/',1,j)else ret=''end if
startslash then ret='/'..ret end if endslash then ret=ret..'/'end return ret end
local function absolutePath(base_path,relative_path)if string.sub(relative_path,
1,1)=='/'then return'/'..string.gsub(relative_path,'^[%./]+','')end local path=
base_path if relative_path~=''then path='/'..path:gsub('[^/]*$','')end path=path
..relative_path path=path:gsub('([^/]*%./)',function(s)if s~='./'then return s
else return''end end)path=string.gsub(path,'/%.$','/')local reduced while
reduced~=path do reduced=path path=string.gsub(reduced,'([^/]*/%.%./)',function(
s)if s~='../../'then return''else return s end end)end path=string.gsub(path,
'([^/]*/%.%.?)$',function(s)if s~='../..'then return''else return s end end)
local reduced while reduced~=path do reduced=path path=string.gsub(reduced,
'^/?%.%./','')end return'/'..path end function M:resolve(other)if type(self)==
'string'then self=M.parse(self)end if type(other)=='string'then other=M.parse(
other)end if other.scheme then return other else other.scheme=self.scheme if not
other.authority or other.authority==''then other:setAuthority(self.authority)if
not other.path or other.path==''then other.path=self.path local query=other.
query if not query or not next(query)then other.query=self.query end else other.
path=absolutePath(self.path,other.path)end end return other end end function M:
normalize()if type(self)=='string'then self=M.parse(self)end if self.path then
local path=self.path path=absolutePath(path,'')path=string.gsub(path,'//+','/')
self.path=path end return self end return M end function
__DARKLUA_BUNDLE_MODULES.e()local ERROR_NON_PROMISE_IN_LIST=
'Non-promise value passed into %s at index %s'local ERROR_NON_LIST=
'Please pass a list of promises to %s'local ERROR_NON_FUNCTION=
'Please pass a handler function to %s!'local MODE_KEY_METATABLE={__mode='k'}
local function isCallable(value)if type(value)=='function'then return true end
if type(value)=='table'then local metatable=getmetatable(value)if metatable and
type(rawget(metatable,'__call'))=='function'then return true end end return
false end local function makeEnum(enumName,members)local enum={}for _,memberName
in ipairs(members)do enum[memberName]=memberName end return setmetatable(enum,{
__index=function(_,k)error(string.format('%s is not in %s!',k,enumName),2)end,
__newindex=function()error(string.format(
'Creating new members in %s is not allowed!',enumName),2)end})end local Error do
Error={Kind=makeEnum('Promise.Error.Kind',{'ExecutionError','AlreadyCancelled',
'NotResolvedInTime','TimedOut'})}Error.__index=Error function Error.new(options,
parent)options=options or{}return setmetatable({error=tostring(options.error)or
'[This error has no error text.]',trace=options.trace,context=options.context,
kind=options.kind,parent=parent,createdTick=os.clock(),createdTrace=debug.
traceback()},Error)end function Error.is(anything)if type(anything)=='table'then
local metatable=getmetatable(anything)if type(metatable)=='table'then return
rawget(anything,'error')~=nil and type(rawget(metatable,'extend'))=='function'
end end return false end function Error.isKind(anything,kind)assert(kind~=nil,
'Argument #2 to Promise.Error.isKind must not be nil')return Error.is(anything)
and anything.kind==kind end function Error:extend(options)options=options or{}
options.kind=options.kind or self.kind return Error.new(options,self)end
function Error:getErrorChain()local runtimeErrors={self}while runtimeErrors[#
runtimeErrors].parent do table.insert(runtimeErrors,runtimeErrors[#runtimeErrors
].parent)end return runtimeErrors end function Error:__tostring()local
errorStrings={string.format('-- Promise.Error(%s) --',self.kind or'?')}for _,
runtimeError in ipairs(self:getErrorChain())do table.insert(errorStrings,table.
concat({runtimeError.trace or runtimeError.error,runtimeError.context},'\n'))end
return table.concat(errorStrings,'\n')end end local function pack(...)return
select('#',...),{...}end local function packResult(success,...)return success,
select('#',...),{...}end local function makeErrorHandler(traceback)assert(
traceback~=nil,'traceback is nil')return function(err)if type(err)=='table'then
return err end return Error.new({error=err,kind=Error.Kind.ExecutionError,trace=
debug.traceback(tostring(err),2),context='Promise created at:\n\n'..traceback})
end end local function runExecutor(traceback,callback,...)return packResult(
xpcall(callback,makeErrorHandler(traceback),...))end local function
createAdvancer(traceback,callback,resolve,reject)return function(...)local ok,
resultLength,result=runExecutor(traceback,callback,...)if ok then resolve(
unpack(result,1,resultLength))else reject(result[1])end end end local function
isEmpty(t)return next(t)==nil end local Promise={Error=Error,Status=makeEnum(
'Promise.Status',{'Started','Resolved','Rejected','Cancelled'}),_getTime=os.
clock,_timeEvent=game:GetService('RunService').Heartbeat,
_unhandledRejectionCallbacks={}}Promise.prototype={}Promise.__index=Promise.
prototype function Promise._new(traceback,callback,parent)if parent~=nil and not
Promise.is(parent)then error(
'Argument #2 to Promise.new must be a promise or nil',2)end local self={_thread=
nil,_source=traceback,_status=Promise.Status.Started,_values=nil,_valuesLength=-
1,_unhandledRejection=true,_queuedResolve={},_queuedReject={},_queuedFinally={},
_cancellationHook=nil,_parent=parent,_consumers=setmetatable({},
MODE_KEY_METATABLE)}if parent and parent._status==Promise.Status.Started then
parent._consumers[self]=true end setmetatable(self,Promise)local function
resolve(...)self:_resolve(...)end local function reject(...)self:_reject(...)end
local function onCancel(cancellationHook)if cancellationHook then if self.
_status==Promise.Status.Cancelled then cancellationHook()else self.
_cancellationHook=cancellationHook end end return self._status==Promise.Status.
Cancelled end self._thread=coroutine.create(function()local ok,_,result=
runExecutor(self._source,callback,resolve,reject,onCancel)if not ok then reject(
result[1])end end)task.spawn(self._thread)return self end function Promise.new(
executor)return Promise._new(debug.traceback(nil,2),executor)end function
Promise:__tostring()return string.format('Promise(%s)',self._status)end function
Promise.defer(executor)local traceback=debug.traceback(nil,2)local promise
promise=Promise._new(traceback,function(resolve,reject,onCancel)local connection
connection=Promise._timeEvent:Connect(function()connection:Disconnect()local ok,
_,result=runExecutor(traceback,executor,resolve,reject,onCancel)if not ok then
reject(result[1])end end)end)return promise end Promise.async=Promise.defer
function Promise.resolve(...)local length,values=pack(...)return Promise._new(
debug.traceback(nil,2),function(resolve)resolve(unpack(values,1,length))end)end
function Promise.reject(...)local length,values=pack(...)return Promise._new(
debug.traceback(nil,2),function(_,reject)reject(unpack(values,1,length))end)end
function Promise._try(traceback,callback,...)local valuesLength,values=pack(...)
return Promise._new(traceback,function(resolve)resolve(callback(unpack(values,1,
valuesLength)))end)end function Promise.try(callback,...)return Promise._try(
debug.traceback(nil,2),callback,...)end function Promise._all(traceback,promises
,amount)if type(promises)~='table'then error(string.format(ERROR_NON_LIST,
'Promise.all'),3)end for i,promise in pairs(promises)do if not Promise.is(
promise)then error(string.format(ERROR_NON_PROMISE_IN_LIST,'Promise.all',
tostring(i)),3)end end if#promises==0 or amount==0 then return Promise.resolve({
})end return Promise._new(traceback,function(resolve,reject,onCancel)local
resolvedValues={}local newPromises={}local resolvedCount=0 local rejectedCount=0
local done=false local function cancel()for _,promise in ipairs(newPromises)do
promise:cancel()end end local function resolveOne(i,...)if done then return end
resolvedCount=resolvedCount+1 if amount==nil then resolvedValues[i]=...else
resolvedValues[resolvedCount]=...end if resolvedCount>=(amount or#promises)then
done=true resolve(resolvedValues)cancel()end end onCancel(cancel)for i,promise
in ipairs(promises)do newPromises[i]=promise:andThen(function(...)resolveOne(i,
...)end,function(...)rejectedCount=rejectedCount+1 if amount==nil or#promises-
rejectedCount<amount then cancel()done=true reject(...)end end)end if done then
cancel()end end)end function Promise.all(...)local promises={...}if type(
promises[1])=='table'and not Promise.is(promises[1])then promises=promises[1]end
return Promise._all(debug.traceback(nil,2),promises)end function Promise.fold(
list,reducer,initialValue)assert(type(list)=='table',
'Bad argument #1 to Promise.fold: must be a table')assert(isCallable(reducer),
'Bad argument #2 to Promise.fold: must be a function')local accumulator=Promise.
resolve(initialValue)return Promise.each(list,function(resolvedElement,i)
accumulator=accumulator:andThen(function(previousValueResolved)return reducer(
previousValueResolved,resolvedElement,i)end)end):andThen(function()return
accumulator end)end function Promise.some(promises,count)assert(type(count)==
'number','Bad argument #2 to Promise.some: must be a number')return Promise.
_all(debug.traceback(nil,2),promises,count)end function Promise.any(promises)
return Promise._all(debug.traceback(nil,2),promises,1):andThen(function(values)
return values[1]end)end function Promise.allSettled(promises)if type(promises)~=
'table'then error(string.format(ERROR_NON_LIST,'Promise.allSettled'),2)end for i
,promise in pairs(promises)do if not Promise.is(promise)then error(string.
format(ERROR_NON_PROMISE_IN_LIST,'Promise.allSettled',tostring(i)),2)end end if#
promises==0 then return Promise.resolve({})end return Promise._new(debug.
traceback(nil,2),function(resolve,_,onCancel)local fates={}local newPromises={}
local finishedCount=0 local function resolveOne(i,...)finishedCount=
finishedCount+1 fates[i]=...if finishedCount>=#promises then resolve(fates)end
end onCancel(function()for _,promise in ipairs(newPromises)do promise:cancel()
end end)for i,promise in ipairs(promises)do newPromises[i]=promise:finally(
function(...)resolveOne(i,...)end)end end)end function Promise.race(promises)
assert(type(promises)=='table',string.format(ERROR_NON_LIST,'Promise.race'))for
i,promise in pairs(promises)do assert(Promise.is(promise),string.format(
ERROR_NON_PROMISE_IN_LIST,'Promise.race',tostring(i)))end return Promise._new(
debug.traceback(nil,2),function(resolve,reject,onCancel)local newPromises={}
local finished=false local function cancel()for _,promise in ipairs(newPromises)
do promise:cancel()end end local function finalize(callback)return function(...)
cancel()finished=true return callback(...)end end if onCancel(finalize(reject))
then return end for i,promise in ipairs(promises)do newPromises[i]=promise:
andThen(finalize(resolve),finalize(reject))end if finished then cancel()end end)
end function Promise.each(list,predicate)assert(type(list)=='table',string.
format(ERROR_NON_LIST,'Promise.each'))assert(isCallable(predicate),string.
format(ERROR_NON_FUNCTION,'Promise.each'))return Promise._new(debug.traceback(
nil,2),function(resolve,reject,onCancel)local results={}local promisesToCancel={
}local cancelled=false local function cancel()for _,promiseToCancel in ipairs(
promisesToCancel)do promiseToCancel:cancel()end end onCancel(function()cancelled
=true cancel()end)local preprocessedList={}for index,value in ipairs(list)do if
Promise.is(value)then if value:getStatus()==Promise.Status.Cancelled then
cancel()return reject(Error.new({error='Promise is cancelled',kind=Error.Kind.
AlreadyCancelled,context=string.format(
[[The Promise that was part of the array at index %d passed into Promise.each was already cancelled when Promise.each began.

That Promise was created at:

%s]]
,index,value._source)}))elseif value:getStatus()==Promise.Status.Rejected then
cancel()return reject(select(2,value:await()))end local ourPromise=value:
andThen(function(...)return...end)table.insert(promisesToCancel,ourPromise)
preprocessedList[index]=ourPromise else preprocessedList[index]=value end end
for index,value in ipairs(preprocessedList)do if Promise.is(value)then local
success success,value=value:await()if not success then cancel()return reject(
value)end end if cancelled then return end local predicatePromise=Promise.
resolve(predicate(value,index))table.insert(promisesToCancel,predicatePromise)
local success,result=predicatePromise:await()if not success then cancel()return
reject(result)end results[index]=result end resolve(results)end)end function
Promise.is(object)if type(object)~='table'then return false end local
objectMetatable=getmetatable(object)if objectMetatable==Promise then return true
elseif objectMetatable==nil then return isCallable(object.andThen)elseif type(
objectMetatable)=='table'and type(rawget(objectMetatable,'__index'))=='table'and
isCallable(rawget(rawget(objectMetatable,'__index'),'andThen'))then return true
end return false end function Promise.promisify(callback)return function(...)
return Promise._try(debug.traceback(nil,2),callback,...)end end do local first
local connection function Promise.delay(seconds)assert(type(seconds)=='number',
'Bad argument #1 to Promise.delay, must be a number.')if not(seconds>=
1.6666666666666665E-2)or seconds==math.huge then seconds=1.6666666666666665E-2
end return Promise._new(debug.traceback(nil,2),function(resolve,_,onCancel)local
startTime=Promise._getTime()local endTime=startTime+seconds local node={resolve=
resolve,startTime=startTime,endTime=endTime}if connection==nil then first=node
connection=Promise._timeEvent:Connect(function()local threadStart=Promise.
_getTime()while first~=nil and first.endTime<threadStart do local current=first
first=current.next if first==nil then connection:Disconnect()connection=nil else
first.previous=nil end current.resolve(Promise._getTime()-current.startTime)end
end)else if first.endTime<endTime then local current=first local next=current.
next while next~=nil and next.endTime<endTime do current=next next=current.next
end current.next=node node.previous=current if next~=nil then node.next=next
next.previous=node end else node.next=first first.previous=node first=node end
end onCancel(function()local next=node.next if first==node then if next==nil
then connection:Disconnect()connection=nil else next.previous=nil end first=next
else local previous=node.previous previous.next=next if next~=nil then next.
previous=previous end end end)end)end end function Promise.prototype:timeout(
seconds,rejectionValue)local traceback=debug.traceback(nil,2)return Promise.
race({Promise.delay(seconds):andThen(function()return Promise.reject(
rejectionValue==nil and Error.new({kind=Error.Kind.TimedOut,error='Timed out',
context=string.format(
'Timeout of %d seconds exceeded.\n:timeout() called at:\n\n%s',seconds,traceback
)})or rejectionValue)end),self})end function Promise.prototype:getStatus()return
self._status end function Promise.prototype:_andThen(traceback,successHandler,
failureHandler)self._unhandledRejection=false return Promise._new(traceback,
function(resolve,reject)local successCallback=resolve if successHandler then
successCallback=createAdvancer(traceback,successHandler,resolve,reject)end local
failureCallback=reject if failureHandler then failureCallback=createAdvancer(
traceback,failureHandler,resolve,reject)end if self._status==Promise.Status.
Started then table.insert(self._queuedResolve,successCallback)table.insert(self.
_queuedReject,failureCallback)elseif self._status==Promise.Status.Resolved then
successCallback(unpack(self._values,1,self._valuesLength))elseif self._status==
Promise.Status.Rejected then failureCallback(unpack(self._values,1,self.
_valuesLength))elseif self._status==Promise.Status.Cancelled then reject(Error.
new({error='Promise is cancelled',kind=Error.Kind.AlreadyCancelled,context=
'Promise created at\n\n'..traceback}))end end,self)end function Promise.
prototype:andThen(successHandler,failureHandler)assert(successHandler==nil or
isCallable(successHandler),string.format(ERROR_NON_FUNCTION,'Promise:andThen'))
assert(failureHandler==nil or isCallable(failureHandler),string.format(
ERROR_NON_FUNCTION,'Promise:andThen'))return self:_andThen(debug.traceback(nil,2
),successHandler,failureHandler)end function Promise.prototype:andThenAsync(
successHandler,failureHandler)assert(successHandler==nil or isCallable(
successHandler),string.format(ERROR_NON_FUNCTION,'Promise:andThenAsync'))assert(
failureHandler==nil or isCallable(failureHandler),string.format(
ERROR_NON_FUNCTION,'Promise:andThenAsync'))return self:_andThen(debug.traceback(
nil,2),function(...)local length,values=pack(...)return Promise.defer(function(
resolve)resolve(unpack(values,1,length))end)end,function(...)local length,values
=pack(...)return Promise.defer(function(_,reject)reject(unpack(values,1,length))
end)end):andThen(successHandler,failureHandler)end function Promise.prototype:
catch(failureHandler)assert(failureHandler==nil or isCallable(failureHandler),
string.format(ERROR_NON_FUNCTION,'Promise:catch'))return self:_andThen(debug.
traceback(nil,2),nil,failureHandler)end function Promise.prototype:tap(
tapHandler)assert(isCallable(tapHandler),string.format(ERROR_NON_FUNCTION,
'Promise:tap'))return self:_andThen(debug.traceback(nil,2),function(...)local
callbackReturn=tapHandler(...)if Promise.is(callbackReturn)then local length,
values=pack(...)return callbackReturn:andThen(function()return unpack(values,1,
length)end)end return...end)end function Promise.prototype:andThenCall(callback,
...)assert(isCallable(callback),string.format(ERROR_NON_FUNCTION,
'Promise:andThenCall'))local length,values=pack(...)return self:_andThen(debug.
traceback(nil,2),function()return callback(unpack(values,1,length))end)end
function Promise.prototype:andThenReturn(...)local length,values=pack(...)return
self:_andThen(debug.traceback(nil,2),function()return unpack(values,1,length)end
)end function Promise.prototype:cancel()if self._status~=Promise.Status.Started
then return end self._status=Promise.Status.Cancelled if self._cancellationHook
then self._cancellationHook()end coroutine.close(self._thread)if self._parent
then self._parent:_consumerCancelled(self)end for child in pairs(self._consumers
)do child:cancel()end self:_finalize()end function Promise.prototype:
_consumerCancelled(consumer)if self._status~=Promise.Status.Started then return
end self._consumers[consumer]=nil if next(self._consumers)==nil then self:
cancel()end end function Promise.prototype:_finally(traceback,finallyHandler,
onlyOk)if not onlyOk then self._unhandledRejection=false end return Promise.
_new(traceback,function(resolve,reject)local finallyCallback=resolve if
finallyHandler then finallyCallback=createAdvancer(traceback,finallyHandler,
resolve,reject)end if onlyOk then local callback=finallyCallback finallyCallback
=function(...)if self._status==Promise.Status.Rejected then return resolve(self)
end return callback(...)end end if self._status==Promise.Status.Started then
table.insert(self._queuedFinally,finallyCallback)else finallyCallback(self.
_status)end end,self)end function Promise.prototype:finally(finallyHandler)
assert(finallyHandler==nil or isCallable(finallyHandler),string.format(
ERROR_NON_FUNCTION,'Promise:finally'))return self:_finally(debug.traceback(nil,2
),finallyHandler)end function Promise.prototype:finallyCall(callback,...)assert(
isCallable(callback),string.format(ERROR_NON_FUNCTION,'Promise:finallyCall'))
local length,values=pack(...)return self:_finally(debug.traceback(nil,2),
function()return callback(unpack(values,1,length))end)end function Promise.
prototype:finallyReturn(...)local length,values=pack(...)return self:_finally(
debug.traceback(nil,2),function()return unpack(values,1,length)end)end function
Promise.prototype:done(finallyHandler)assert(finallyHandler==nil or isCallable(
finallyHandler),string.format(ERROR_NON_FUNCTION,'Promise:done'))return self:
_finally(debug.traceback(nil,2),finallyHandler,true)end function Promise.
prototype:doneCall(callback,...)assert(isCallable(callback),string.format(
ERROR_NON_FUNCTION,'Promise:doneCall'))local length,values=pack(...)return self:
_finally(debug.traceback(nil,2),function()return callback(unpack(values,1,length
))end,true)end function Promise.prototype:doneReturn(...)local length,values=
pack(...)return self:_finally(debug.traceback(nil,2),function()return unpack(
values,1,length)end,true)end function Promise.prototype:awaitStatus()self.
_unhandledRejection=false if self._status==Promise.Status.Started then local
thread=coroutine.running()self:finally(function()task.spawn(thread)end)coroutine
.yield()end if self._status==Promise.Status.Resolved then return self._status,
unpack(self._values,1,self._valuesLength)elseif self._status==Promise.Status.
Rejected then return self._status,unpack(self._values,1,self._valuesLength)end
return self._status end local function awaitHelper(status,...)return status==
Promise.Status.Resolved,...end function Promise.prototype:await()return
awaitHelper(self:awaitStatus())end local function expectHelper(status,...)if
status~=Promise.Status.Resolved then error((...)==nil and
'Expected Promise rejected with no value.'or(...),3)end return...end function
Promise.prototype:expect()return expectHelper(self:awaitStatus())end Promise.
prototype.awaitValue=Promise.prototype.expect function Promise.prototype:_unwrap
()if self._status==Promise.Status.Started then error(
'Promise has not resolved or rejected.',2)end local success=self._status==
Promise.Status.Resolved return success,unpack(self._values,1,self._valuesLength)
end function Promise.prototype:_resolve(...)if self._status~=Promise.Status.
Started then if Promise.is((...))then(...):_consumerCancelled(self)end return
end if Promise.is((...))then if select('#',...)>1 then local message=string.
format(
[[When returning a Promise from andThen, extra arguments are discarded! See:

%s]]
,self._source)warn(message)end local chainedPromise=...local promise=
chainedPromise:andThen(function(...)self:_resolve(...)end,function(...)local
maybeRuntimeError=chainedPromise._values[1]if chainedPromise._error then
maybeRuntimeError=Error.new({error=chainedPromise._error,kind=Error.Kind.
ExecutionError,context=
[=[[No stack trace available as this Promise originated from an older version of the Promise library (< v2)]]=]
})end if Error.isKind(maybeRuntimeError,Error.Kind.ExecutionError)then return
self:_reject(maybeRuntimeError:extend({error=
'This Promise was chained to a Promise that errored.',trace='',context=string.
format(
[[The Promise at:

%s
...Rejected because it was chained to the following Promise, which encountered an error:
]]
,self._source)}))end self:_reject(...)end)if promise._status==Promise.Status.
Cancelled then self:cancel()elseif promise._status==Promise.Status.Started then
self._parent=promise promise._consumers[self]=true end return end self._status=
Promise.Status.Resolved self._valuesLength,self._values=pack(...)for _,callback
in ipairs(self._queuedResolve)do coroutine.wrap(callback)(...)end self:
_finalize()end function Promise.prototype:_reject(...)if self._status~=Promise.
Status.Started then return end self._status=Promise.Status.Rejected self.
_valuesLength,self._values=pack(...)if not isEmpty(self._queuedReject)then for _
,callback in ipairs(self._queuedReject)do coroutine.wrap(callback)(...)end else
local err=tostring((...))coroutine.wrap(function()Promise._timeEvent:Wait()if
not self._unhandledRejection then return end local message=string.format(
'Unhandled Promise rejection:\n\n%s\n\n%s',err,self._source)for _,callback in
ipairs(Promise._unhandledRejectionCallbacks)do task.spawn(callback,self,unpack(
self._values,1,self._valuesLength))end if Promise.TEST then return end warn(
message)end)()end self:_finalize()end function Promise.prototype:_finalize()for
_,callback in ipairs(self._queuedFinally)do coroutine.wrap(callback)(self.
_status)end self._queuedFinally=nil self._queuedReject=nil self._queuedResolve=
nil if not Promise.TEST then self._parent=nil self._consumers=nil end task.
defer(coroutine.close,self._thread)end function Promise.prototype:now(
rejectionValue)local traceback=debug.traceback(nil,2)if self._status==Promise.
Status.Resolved then return self:_andThen(traceback,function(...)return...end)
else return Promise.reject(rejectionValue==nil and Error.new({kind=Error.Kind.
NotResolvedInTime,error='This Promise was not resolved in time for :now()',
context=':now() was called at:\n\n'..traceback})or rejectionValue)end end
function Promise.retry(callback,times,...)assert(isCallable(callback),
'Parameter #1 to Promise.retry must be a function')assert(type(times)=='number',
'Parameter #2 to Promise.retry must be a number')local args,length={...},select(
'#',...)return Promise.resolve(callback(...)):catch(function(...)if times>0 then
return Promise.retry(callback,times-1,unpack(args,1,length))else return Promise.
reject(...)end end)end function Promise.retryWithDelay(callback,times,seconds,
...)assert(isCallable(callback),
'Parameter #1 to Promise.retry must be a function')assert(type(times)=='number',
'Parameter #2 (times) to Promise.retry must be a number')assert(type(seconds)==
'number','Parameter #3 (seconds) to Promise.retry must be a number')local args,
length={...},select('#',...)return Promise.resolve(callback(...)):catch(function
(...)if times>0 then Promise.delay(seconds):await()return Promise.
retryWithDelay(callback,times-1,seconds,unpack(args,1,length))else return
Promise.reject(...)end end)end function Promise.fromEvent(event,predicate)
predicate=predicate or function()return true end return Promise._new(debug.
traceback(nil,2),function(resolve,_,onCancel)local connection local
shouldDisconnect=false local function disconnect()connection:Disconnect()
connection=nil end connection=event:Connect(function(...)local callbackValue=
predicate(...)if callbackValue==true then resolve(...)if connection then
disconnect()else shouldDisconnect=true end elseif type(callbackValue)~='boolean'
then error('Promise.fromEvent predicate should always return a boolean')end end)
if shouldDisconnect and connection then return disconnect()end onCancel(
disconnect)end)end function Promise.onUnhandledRejection(callback)table.insert(
Promise._unhandledRejectionCallbacks,callback)return function()local index=table
.find(Promise._unhandledRejectionCallbacks,callback)if index then table.remove(
Promise._unhandledRejectionCallbacks,index)end end end return Promise end
function __DARKLUA_BUNDLE_MODULES.f()local module=__DARKLUA_BUNDLE_MODULES.load(
'e')return module end function __DARKLUA_BUNDLE_MODULES.g()local httpservice=
game:GetService('HttpService')local function enc(t)return httpservice:
JSONEncode(t)end local function dec(s)return httpservice:JSONDecode(s)end return
{['enc']=enc,['dec']=dec}end function __DARKLUA_BUNDLE_MODULES.h()return
function(t)local nt=setmetatable({},{__index=function(self,idx)return rawget(
self,idx:lower())end,__newindex=function(self,idx,val)rawset(self,idx:lower(),
val)end})for k,v in pairs(t)do nt[k]=v end return nt end end function
__DARKLUA_BUNDLE_MODULES.i()local json=__DARKLUA_BUNDLE_MODULES.load('g')local
Url=__DARKLUA_BUNDLE_MODULES.load('d')local function maybe_number(str)local num=
tonumber(str)return num or str end local function trim(s)s=s or''while s:sub(1,1
)==' 'do s=s:sub(2)end while s:sub(-1,-1)==' 'do s=s:sub(1,-2)end return s end
local Cookie={}Cookie.__index=Cookie function Cookie.new(name,value,opts)local
self=setmetatable({},Cookie)opts=opts or{}self.name=name self.value=value self.
domain=opts.domain or''self.path=opts.path or''return self end function Cookie.
fromSet(s)local opts={}local args=s:split(';')local nv=args[1]:split('=')local
name,value=trim(nv[1]),trim(nv[2])for i=2,#args do local kv=args[i]:split('=')
local k,v=trim(kv[1]):lower(),trim(kv[2])opts[k]=v end return Cookie.new(name,
value,opts)end function Cookie:matches(url)if not self.domain then return true
end local u=Url.parse(url)if self.domain:sub(1,1)=='.'then if not(u.host:sub(-#
self.domain,-1)==self.domain or u.host==self.domain:sub(2))then return false end
else if u.host~=self.domain then return false end end if self.path then if not u
.path:sub(1,#self.path)==self.path then return false end end return true end
local CookieJar={}CookieJar.__index=CookieJar function CookieJar.new()local self
=setmetatable({},CookieJar)self.__cookiejar=true self.cookies={}return self end
function CookieJar:insert(name,value,opts)self.cookies[name]=Cookie.new(name,
value,opts)return self end function CookieJar:SetCookie(s)local c=Cookie.
fromSet(s)self.cookies[c.name]=c end function CookieJar:delete(name)self.cookies
[name]=nil end function CookieJar:string(url)local str=''for _,cookie in pairs(
self.cookies)do if str then str=str..'; 'end str=str..('%s=%s'):format(cookie.
name,cookie.value)end return str end function CookieJar:__tostring()return json.
enc(self.domains)end return CookieJar end function __DARKLUA_BUNDLE_MODULES.j()
local CaseInsensitive=__DARKLUA_BUNDLE_MODULES.load('h')local html=
__DARKLUA_BUNDLE_MODULES.load('c')local json=__DARKLUA_BUNDLE_MODULES.load('g')
local CookieJar=__DARKLUA_BUNDLE_MODULES.load('i')local html_types={'text/html',
'application/xhtml+xml'}local Response={}Response.__index=Response function
Response.new(req,resp,rt)local self=setmetatable({},Response)self.request=req
self.response_time=rt self.timestamp=self.request.timestamp self.url=req.url
self.method=req.method self.code=resp.StatusCode self.status_code=resp.
StatusCode self.success=resp.Success self.ok=self.status_code>=200 and self.
status_code<300 self.message=resp.StatusMessage self.headers=CaseInsensitive(
resp.Headers)self.content=resp.Body self.text=resp.Body self.headers[
'content-type']=self.headers['content-type']or'text/plain'self.from_cache=false
local type_encoding=self.headers['content-type']:split(';')self.content_type=
type_encoding[1]:lower()self.encoding=(type_encoding[2]and type_encoding[2]:
split('=')[2])or''self.content_length=#self.text self.cookies=CookieJar.new()if
self.headers['set-cookie']then self.cookies:SetCookie(self.headers['set-cookie']
)end return self end function Response:expand()end function Response:__tostring(
)return self.text end function Response:json()local succ,data=pcall(function()
return json.dec(self.text)end)if not succ then error((
'[http] Failed to convert response content to JSON:\n%s'):format(self.text))end
return data end function Response:html(ignore_content_type)if
ignore_content_type or table.find(html_types,self.content_type)then return html.
parse(self.text,100000,tostring(self.url))else error(
'[http] Response is not specified as HTML.')end end function Response:xml(
ignore_content_type)if ignore_content_type or self.content_type:find('+xml')or
self.content_type:find('/xml')then return html.parse(self.text,100000)else
error('[http] Response is not specified as XML.')end end return Response end
function __DARKLUA_BUNDLE_MODULES.k()local RateLimiter={}RateLimiter.__index=
RateLimiter local function log(s)return s end if not RateLimiter.ratelimit then
RateLimiter.ratelimit={}end function RateLimiter.get(id,rate,window_size)local
self=setmetatable({},RateLimiter)if not RateLimiter.ratelimit[id]then
RateLimiter.ratelimit[id]={}RateLimiter.ratelimit[id].windows={}end RateLimiter.
ratelimit[id].window_size=window_size RateLimiter.ratelimit[id].rate=rate self.
id=id self.window_size=RateLimiter.ratelimit[id].window_size self.rate=
RateLimiter.ratelimit[id].rate log('[ratelimit] Created RateLimiter with id',
self.id)return self end function RateLimiter:window()return math.floor(tick()/
self.window_size)end function RateLimiter:progress()return(tick()%self.
window_size)/self.window_size end function RateLimiter:increment()local w=self:
window()log('[ratelimit] Incrementing window',w)if not RateLimiter.ratelimit[
self.id].windows[w]then RateLimiter.ratelimit[self.id].windows[w]=0 end
RateLimiter.ratelimit[self.id].windows[w]=RateLimiter.ratelimit[self.id].windows
[w]+1 return RateLimiter.ratelimit[self.id].windows[w]end function RateLimiter:
weighted(i)i=i or 0 local p=self:progress()local w=self:window()local current=(
RateLimiter.ratelimit[self.id].windows[w]or 0)+i local prev=RateLimiter.
ratelimit[self.id].windows[w-1]or 0 return current*p+prev*(1-p)end function
RateLimiter:consumption()return self:weighted()/self.rate end function
RateLimiter:request()if self:weighted(1)>self.rate then return false else self:
increment()return true end end return RateLimiter end function
__DARKLUA_BUNDLE_MODULES.l()local _U={}function _U.deprecate(method,version,name
)return function(...)if version then warn((
[[[http] %s deprecated in version %s. See documentation at http://requests.paric.xyz/]]
):format(name,version or'Function'))else warn((
[[[http] %s deprecated. See documentation at http://requests.paric.xyz/]]):
format(name or'Function'))end return method(...)end end return _U end function
__DARKLUA_BUNDLE_MODULES.m()local MS=game:GetService('MessagingService')local DS
=game:GetService('DataStoreService')local RS=game:GetService('RunService')local
json=__DARKLUA_BUNDLE_MODULES.load('g')local STUDIO=RS:IsStudio()local function
dlog(...)print('[http]',...)end local Cache={}Cache.settings={}Cache.max_size=
math.huge Cache.data={}function Cache.update_settings(urls,settings)urls=type(
urls)=='table'and urls or{urls}local _concat={}local i=0 while i<#urls do i+=1
local url=urls[i]if url:sub(1,7)=='http://'then urls[i]=url:sub(8)url=urls[i]
elseif url:sub(1,8)=='https://'then urls[i]=url:sub(9)url=urls[i]end if url:sub(
1,2)=='*.'then table.insert(urls,url:sub(3))end if not url:find('/')then table.
insert(urls,url..'/')table.insert(urls,url..'/*')end end for _,url in ipairs(
urls)do Cache.settings[url]=settings if settings.cache_locally==false and not
settings.cache_globally then Cache.settings[url]=nil end end end function Cache.
cache_locally(urls,opts)opts=opts or{}opts.cache_globally=false Cache.
update_settings(urls,opts)end function Cache.cache_globally(urls,opts)opts=opts
or{}opts.cache_globally=true Cache.update_settings(urls,opts)end function Cache.
should_cache(url)url=url:split('?')[1]for key,_ in pairs(Cache.settings)do local
pattern='.*://'..key:gsub('%*','.*')if url:match(pattern)then return key end end
return false end function Cache.is_cached(url,req_id)local setting_key=Cache.
should_cache(url)local settings=Cache.settings[setting_key]if not setting_key
then return false end if Cache.data[req_id]~=nil then if settings.expires then
if tick()-Cache.data[req_id].timestamp>settings.expires then return false end
end return true end if Cache.settings[setting_key].cache_globally then if Cache.
global_cache_index[req_id]then return true else return false end else return
false end end Cache.global_cache_index={}local global_cache_queue={}local
global_cache_enabled,ds_cache=pcall(function()return DS:GetDataStore(
'HttpRequestsCache')end)if global_cache_enabled then local succ,
global_cache_index=pcall(function()return ds_cache:GetAsync('index')or{}end)if
succ then Cache.global_cache_index=global_cache_index Cache.
global_cache_update_interval=20 coroutine.wrap(function()while wait(Cache.
global_cache_update_interval)do pcall(function()local i=0 for k,v in pairs(
global_cache_queue)do ds_cache:SetAsync(k,v)i+=1 end if i>0 then dlog((
'pushing %s requests to global cache index'):format(i))end local index_list={}
ds_cache:UpdateAsync('index',function(idx)idx=idx or{}for k,_ in pairs(
global_cache_queue)do table.insert(index_list,k)idx[k]=true Cache.
global_cache_index[k]=true end return idx end)if not STUDIO then MS:
PublishAsync('RequestsCacheIndex',json.enc(index_list))end global_cache_queue={}
end)end end)()if not STUDIO then MS:SubscribeAsync('RequestsCacheIndex',function
(msg)local append=json.dec(msg.Data)for _,v in ipairs(append)do Cache.
global_cache_index[v]=true end end)end end end function Cache.get_expire(url)
local setting_key=Cache.should_cache(url)return Cache.settings[setting_key].
expires or math.huge end function Cache.get_cached(url,req_id)local setting_key=
Cache.should_cache(url)local server_cached=Cache.data[req_id]if server_cached
then return server_cached,'local'end if global_cache_enabled and Cache.settings[
setting_key].cache_globally then dlog('accessing datastore cache for',req_id)
return ds_cache:GetAsync(req_id),'global'end end function Cache.update_cache(url
,req_id,data)print(('[http] %s added to cache'):format(url))data.timestamp=tick(
)Cache.data[req_id]=data local setting_key=Cache.should_cache(url)if
global_cache_enabled and Cache.settings[setting_key].cache_globally then dlog(
'queued',req_id)global_cache_queue[req_id]=data return end end return Cache end
function __DARKLUA_BUNDLE_MODULES.n()local httpservice=game:GetService(
'HttpService')local Url=__DARKLUA_BUNDLE_MODULES.load('d')local Promise=
__DARKLUA_BUNDLE_MODULES.load('f')local json=__DARKLUA_BUNDLE_MODULES.load('g')
local Response=__DARKLUA_BUNDLE_MODULES.load('j')local CookieJar=
__DARKLUA_BUNDLE_MODULES.load('i')local RateLimiter=__DARKLUA_BUNDLE_MODULES.
load('k')local Util=__DARKLUA_BUNDLE_MODULES.load('l')local Cache=
__DARKLUA_BUNDLE_MODULES.load('m')local Request={}Request.__index=Request
function Request.new(method,url,opts)local self=setmetatable({},Request)opts=
opts or{}local u=Url.parse(url)local headers=opts.headers or{}self.method=method
:upper()self.url=u self.input_url=url self.headers=headers self.query={}self.
data=nil self._ratelimits={RateLimiter.get('http',250,30)}self.ignore_ratelimit=
opts.ignore_ratelimit or false if opts.data then self:set_data(opts.data)end
self:set_query(opts.query or{})local cj=opts.cookies or{}if not cj.__cookiejar
then local jar=CookieJar.new()if cj then for k,v in pairs(cj)do jar:insert(k,v)
end end cj=jar end self.cookies=cj self.headers['Cookie']=cj:string(url)self.
_callback=nil self._log=(opts.log==nil and true)or opts.log return self end
function Request:set_headers(headers)for k,v in pairs(headers)do self.headers[k]
=v end return self end Request.update_headers=Util.deprecate(Request.set_headers
,'0.5','update_headers')function Request:set_query(params)for k,v in pairs(
params)do self.query[k]=v end self.url:setQuery(self.query)return self end
Request.update_query=Util.deprecate(Request.set_headers,'0.5','update_query')
function Request:set_data(data)if type(data)=='table'then if data.__FormData
then self.headers['Content-Type']=data.content_type data=data:build()else data=
json.enc(data)self.headers['Content-Type']='application/json'end end self.data=
data return self end function Request:_ratelimit()for _,rl in ipairs(self.
_ratelimits)do if not rl:request()then return false end end return true end
function Request:_send()local options={['Url']=self.url:build(),Method=self.
method,Headers=self.headers}if self.data~=nil then options.Body=self.data end
local trimmed_url=options.Url:sub(-1,-1)=='/'and options.Url:sub(1,-2)or options
.Url local unique_id=('Request_%s_%s_%s'):format(self.method,trimmed_url,options
.Body or'')if self.method:upper()=='GET'and Cache.is_cached(options.Url,
unique_id)then local st=tick()local data,cache_type=Cache.get_cached(options.Url
,unique_id)if st-data.timestamp<=Cache.get_expire(options.Url)then local resp=
Response.new(self,data,tick()-st)resp.from_cache=true print('[http]',cache_type:
upper(),'CACHE |',resp.method,resp.url)return resp end end local attempts=0
local succ,resp,raw_response=false while attempts<5 do if self.ignore_ratelimit
or self:_ratelimit()then local st=tick()raw_response=httpservice:RequestAsync(
options)resp=Response.new(self,raw_response,tick()-st)self.timestamp=st succ=
true break end warn('[http] Rate limit exceeded. Retrying in 5 seconds')attempts
=attempts+1 wait(5)end if not succ then error(
'[http] Rate limit still exceeded after 5 attempts')end if self._log then local
rl=tostring(math.floor(self._ratelimits[#self._ratelimits]:consumption()*1000)*
0.1)..'%'print('[http]',resp.code,resp.message,'|',resp.method,resp.url,'(',rl,
'ratelimit )')end if self._callback then self._callback(resp)end if self.method:
upper()=='GET'and resp.ok and Cache.should_cache(options.Url)then Cache.
update_cache(options.Url,unique_id,raw_response)end return resp end function
Request:send(promise)if promise then return Promise.new(function(resolve,reject)
local ok,result=pcall(self._send,self)local succ=ok and result.ok if succ then
resolve(result)else if ok then reject({request_sent=true,response=result})else
reject({request_sent=false,error=result})end end end)else return self:_send()end
end function Request:promise()return self:send(true)end return Request end
function __DARKLUA_BUNDLE_MODULES.o()local Request=__DARKLUA_BUNDLE_MODULES.
load('n')local CookieJar=__DARKLUA_BUNDLE_MODULES.load('i')local RateLimiter=
__DARKLUA_BUNDLE_MODULES.load('k')local Util=__DARKLUA_BUNDLE_MODULES.load('l')
local function randomString(l)local s=''for _=1,l do s=s..string.char(math.
random(97,122))end return s end local Session={}Session.__index=Session function
Session.new(base_url)local self=setmetatable({},Session)self.headers={}self.
cookies=CookieJar.new()self.base_url=base_url or''self._ratelimit=nil self.
ignore_ratelimit=false self.before_request=nil self.after_request=nil self.
no_stats=false self.log=true return self end function Session:set_ratelimit(rate
,window)if not rate then self:disable_ratelimit()end window=window or 60 if self
._ratelimit then RateLimiter.ratelimit[self._ratelimit.id]=nil end local rl_id=
'http.session-'..randomString(12)self._ratelimit=RateLimiter.get(rl_id,rate,
window)end function Session:disable_ratelimit()if self._ratelimit then
RateLimiter.ratelimit[self._ratelimit.id]=nil self._ratelimit=nil end end
function Session:set_headers(headers)for k,v in pairs(headers)do self.headers[k]
=v end return self end function Session:Request(method,url,opts)opts=opts or{}if
not(url:sub(1,7)=='http://'or url:sub(1,8)=='https://')then url=self.base_url..
url end local will_log=self.log if opts.log~=nil then will_log=opts.log end
local request=Request.new(method,url,{headers=self.headers,query=opts.query,data
=opts.data,log=will_log,cookies=opts.cookies or self.cookies,ignore_ratelimit=
opts.ignore_ratelimit or self.ignore_ratelimit,no_stats=self.no_stats or false})
if self._ratelimit then table.insert(request._ratelimits,self._ratelimit)end
request:set_headers(opts.headers or{})request._callback=function(resp)for _,
cookie in ipairs(resp.cookies.cookies)do table.insert(self.cookies.cookies,
cookie)end end return request end function Session:request(method,url,opts)opts=
opts or{}local req=self:Request(method,url,opts)return req:send()end Session.
send=Util.deprecate(Session.request,'0.5','Session:send')function Session:
promise_request(method,url,opts)opts=opts or{}local req=self:Request(method,url,
opts)return req:send(true)end Session.promise_send=Util.deprecate(Session.
promise_request,'0.5','Session:promise_send')for _,method in pairs({'GET','POST'
,'HEAD','OPTIONS','PUT','DELETE','PATCH'})do Session[method:lower()]=function(
self,url,opts)return self:send(method,url,opts)end Session['promise_'..method:
lower()]=function(self,url,opts)return self:promise_send(method,url,opts)end end
return Session end function __DARKLUA_BUNDLE_MODULES.p()return{['ez']=
'application/andrew-inset',['aw']='application/applixware',['atom']=
'application/atom+xml',['atomcat']='application/atomcat+xml',['atomsvc']=
'application/atomsvc+xml',['ccxml']='application/ccxml+xml',['cdmia']=
'application/cdmi-capability',['cdmic']='application/cdmi-container',['cdmid']=
'application/cdmi-domain',['cdmio']='application/cdmi-object',['cdmiq']=
'application/cdmi-queue',['cu']='application/cu-seeme',['davmount']=
'application/davmount+xml',['dbk']='application/docbook+xml',['dssc']=
'application/dssc+der',['xdssc']='application/dssc+xml',['ecma']=
'application/ecmascript',['comment+xml']=' .comment+xml',['deviceinfo+xml']=
' .deviceinfo+xml',['providerinfo+xml']=' .providerinfo+xml',['serviceinfo+xml']
=' .serviceinfo+xml',['subscriberinfo+xml']=' .subscriberinfo+xml',['emma']=
'application/emma+xml',['epub']='application/epub+zip',['exi']='application/exi'
,['pfr']='application/font-tdpfr',['gml']='application/gml+xml',['gpx']=
'application/gpx+xml',['gxf']='application/gxf',['stk']=
'application/hyperstudio',['cmd']=' .cmd',['response']=' .response',['vnd']=
' .vnd',['ink']='application/inkml+xml',['inkml']='application/inkml+xml',[
'ipfix']='application/ipfix',['jar']='application/java-archive',['ser']=
'application/java-serialized-object',['class']='application/java-vm',['js']=
'application/javascript',['json']='application/json',['jsonml']=
'application/jsonml+json',['lostxml']='application/lost+xml',['hqx']=
'application/mac-binhex40',['cpt']='application/mac-compactpro',['mads']=
'application/mads+xml',['mrc']='application/marc',['mrcx']=
'application/marcxml+xml',['ma']='application/mathematica',['nb']=
'application/mathematica',['mb']='application/mathematica',['mathml']=
'application/mathml+xml',['mbox']='application/mbox',['mscml']=
'application/mediaservercontrol+xml',['metalink']='application/metalink+xml',[
'meta4']='application/metalink4+xml',['mets']='application/mets+xml',['mods']=
'application/mods+xml',['m21']='application/mp21',['mp21']='application/mp21',[
'mp4s']='application/mp4',['doc']='application/msword',['dot']=
'application/msword',['mxf']='application/mxf',['bin']=
'application/octet-stream',['dms']='application/octet-stream',['lrf']=
'application/octet-stream',['mar']='application/octet-stream',['so']=
'application/octet-stream',['dist']='application/octet-stream',['distz']=
'application/octet-stream',['pkg']='application/octet-stream',['bpk']=
'application/octet-stream',['dump']='application/octet-stream',['elc']=
'application/octet-stream',['deploy']='application/octet-stream',['oda']=
'application/oda',['opf']='application/oebps-package+xml',['ogx']=
'application/ogg',['omdoc']='application/omdoc+xml',['onetoc']=
'application/onenote',['onetoc2']='application/onenote',['onetmp']=
'application/onenote',['onepkg']='application/onenote',['oxps']=
'application/oxps',['xer']='application/patch-ops-error+xml',['pdf']=
'application/pdf',['pgp']='application/pgp-encrypted',['asc']=
'application/pgp-signature',['sig']='application/pgp-signature',['prf']=
'application/pics-rules',['p10']='application/pkcs10',['p7m']=
'application/pkcs7-mime',['p7c']='application/pkcs7-mime',['p7s']=
'application/pkcs7-signature',['p8']='application/pkcs8',['ac']=
'application/pkix-attr-cert',['cer']='application/pkix-cert',['crl']=
'application/pkix-crl',['pkipath']='application/pkix-pkipath',['pki']=
'application/pkixcmp',['pls']='application/pls+xml',['ai']=
'application/postscript',['eps']='application/postscript',['ps']=
'application/postscript',['alvestrand.titrax-sheet']=' .alvestrand.titrax-sheet'
,['cww']='application/prs.cww',['hpub+zip']=' .hpub+zip',['nprend']=' .nprend',[
'plucker']=' .plucker',['rdf-xml-crypt']=' .rdf-xml-crypt',['xsf+xml']=
' .xsf+xml',['pskcxml']='application/pskc+xml',['rdf']='application/rdf+xml',[
'rif']='application/reginfo+xml',['rnc']='application/relax-ng-compact-syntax',[
'rl']='application/resource-lists+xml',['rld']=
'application/resource-lists-diff+xml',['rs']='application/rls-services+xml',[
'gbr']='application/rpki-ghostbusters',['mft']='application/rpki-manifest',[
'roa']='application/rpki-roa',['rsd']='application/rsd+xml',['rss']=
'application/rss+xml',['rtf']='application/rtf',['sbml']='application/sbml+xml',
['scq']='application/scvp-cv-request',['scs']='application/scvp-cv-response',[
'spq']='application/scvp-vp-request',['spp']='application/scvp-vp-response',[
'sdp']='application/sdp',['setpay']='application/set-payment-initiation',[
'setreg']='application/set-registration-initiation',['shf']=
'application/shf+xml',['smi']='application/smil+xml',['smil']=
'application/smil+xml',['rq']='application/sparql-query',['srx']=
'application/sparql-results+xml',['gram']='application/srgs',['grxml']=
'application/srgs+xml',['sru']='application/sru+xml',['ssdl']=
'application/ssdl+xml',['ssml']='application/ssml+xml',['tei']=
'application/tei+xml',['teicorpus']='application/tei+xml',['tfi']=
'application/thraud+xml',['tsd']='application/timestamped-data',['scriptfile']=
' .scriptfile',['3gpp-prose+xml']=' .3gpp-prose+xml',['3gpp-prose-pc3ch+xml']=
' .3gpp-prose-pc3ch+xml',['3gpp.access-transfer-events+xml']=
' .3gpp.access-transfer-events+xml',['3gpp.bsf+xml']=' .3gpp.bsf+xml',[
'3gpp.mid-call+xml']=' .3gpp.mid-call+xml',['plb']=
'application/vnd.3gpp.pic-bw-large',['psb']='application/vnd.3gpp.pic-bw-small',
['pvb']='application/vnd.3gpp.pic-bw-var',['3gpp.sms']=' .3gpp.sms',[
'3gpp.sms+xml']=' .3gpp.sms+xml',['3gpp.srvcc-ext+xml']=' .3gpp.srvcc-ext+xml',[
'3gpp.srvcc-info+xml']=' .3gpp.srvcc-info+xml',['3gpp.state-and-event-info+xml']
=' .3gpp.state-and-event-info+xml',['3gpp.ussd+xml']=' .3gpp.ussd+xml',[
'3gpp2.bcmcsinfo+xml']=' .3gpp2.bcmcsinfo+xml',['3gpp2.sms']=' .3gpp2.sms',[
'tcap']='application/vnd.3gpp2.tcap',['3lightssoftware.imagescal']=
' .3lightssoftware.imagescal',['pwn']='application/vnd.3m.post-it-notes',['aso']
='application/vnd.accpac.simply.aso',['imp']='application/vnd.accpac.simply.imp'
,['acu']='application/vnd.acucobol',['atc']='application/vnd.acucorp',['acutc']=
'application/vnd.acucorp',['air']=
'application/vnd.adobe.air-application-installer-package+zip',[
'adobe.flash.movie']=' .adobe.flash.movie',['fcdt']=
'application/vnd.adobe.formscentral.fcdt',['fxp']='application/vnd.adobe.fxp',[
'fxpl']='application/vnd.adobe.fxp',['adobe.partial-upload']=
' .adobe.partial-upload',['xdp']='application/vnd.adobe.xdp+xml',['xfdf']=
'application/vnd.adobe.xfdf',['aether.imp']=' .aether.imp',['ah-barcode']=
' .ah-barcode',['ahead']='application/vnd.ahead.space',['azf']=
'application/vnd.airzip.filesecure.azf',['azs']=
'application/vnd.airzip.filesecure.azs',['azw']='application/vnd.amazon.ebook',[
'amazon.mobi8-ebook']=' .amazon.mobi8-ebook',['acc']=
'application/vnd.americandynamics.acc',['ami']='application/vnd.amiga.ami',[
'amundsen.maze+xml']=' .amundsen.maze+xml',['apk']=
'application/vnd.android.package-archive',['anki']=' .anki',['cii']=
'application/vnd.anser-web-certificate-issue-initiation',['fti']=
'application/vnd.anser-web-funds-transfer-initiation',['atx']=
'application/vnd.antix.game-component',['apache.thrift.binary']=
' .apache.thrift.binary',['apache.thrift.compact']=' .apache.thrift.compact',[
'apache.thrift.json']=' .apache.thrift.json',['api+json']=' .api+json',['mpkg']=
'application/vnd.apple.installer+xml',['m3u8']='application/vnd.apple.mpegurl',[
'arastra.swi']=' .arastra.swi',['swi']='application/vnd.aristanetworks.swi',[
'artsquare']=' .artsquare',['iota']='application/vnd.astraea-software.iota',[
'aep']='application/vnd.audiograph',['autopackage']=' .autopackage',[
'avistar+xml']=' .avistar+xml',['balsamiq.bmml+xml']=' .balsamiq.bmml+xml',[
'balsamiq.bmpr']=' .balsamiq.bmpr',['bekitzur-stech+json']=
' .bekitzur-stech+json',['biopax.rdf+xml']=' .biopax.rdf+xml',['mpm']=
'application/vnd.blueice.multipass',['bluetooth.ep.oob']=' .bluetooth.ep.oob',[
'bluetooth.le.oob']=' .bluetooth.le.oob',['bmi']='application/vnd.bmi',['rep']=
'application/vnd.businessobjects',['cab-jscript']=' .cab-jscript',['canon-cpdl']
=' .canon-cpdl',['canon-lips']=' .canon-lips',['cendio.thinlinc.clientconf']=
' .cendio.thinlinc.clientconf',['century-systems.tcp_stream']=
' .century-systems.tcp_stream',['cdxml']='application/vnd.chemdraw+xml',[
'chess-pgn']=' .chess-pgn',['mmd']='application/vnd.chipnuts.karaoke-mmd',['cdy'
]='application/vnd.cinderella',['cirpack.isdn-ext']=' .cirpack.isdn-ext',[
'citationstyles.style+xml']=' .citationstyles.style+xml',['cla']=
'application/vnd.claymore',['rp9']='application/vnd.cloanto.rp9',['c4g']=
'application/vnd.clonk.c4group',['c4d']='application/vnd.clonk.c4group',['c4f']=
'application/vnd.clonk.c4group',['c4p']='application/vnd.clonk.c4group',['c4u']=
'application/vnd.clonk.c4group',['c11amc']=
'application/vnd.cluetrust.cartomobile-config',['c11amz']=
'application/vnd.cluetrust.cartomobile-config-pkg',['coffeescript']=
' .coffeescript',['collection+json']=' .collection+json',['collection.doc+json']
=' .collection.doc+json',['collection.next+json']=' .collection.next+json',[
'comicbook+zip']=' .comicbook+zip',['commerce-battelle']=' .commerce-battelle',[
'csp']='application/vnd.commonspace',['cdbcmsg']='application/vnd.contact.cmsg',
['coreos.ignition+json']=' .coreos.ignition+json',['cmc']=
'application/vnd.cosmocaller',['clkx']='application/vnd.crick.clicker',['clkk']=
'application/vnd.crick.clicker.keyboard',['clkp']=
'application/vnd.crick.clicker.palette',['clkt']=
'application/vnd.crick.clicker.template',['clkw']=
'application/vnd.crick.clicker.wordbank',['wbs']=
'application/vnd.criticaltools.wbs+xml',['pml']='application/vnd.ctc-posml',[
'ctct.ws+xml']=' .ctct.ws+xml',['cups-pdf']=' .cups-pdf',['cups-postscript']=
' .cups-postscript',['ppd']='application/vnd.cups-ppd',['cups-raster']=
' .cups-raster',['cups-raw']=' .cups-raw',['car']='application/vnd.curl.car',[
'pcurl']='application/vnd.curl.pcurl',['cyan.dean.root+xml']=
' .cyan.dean.root+xml',['cybank']=' .cybank',['dart']='application/vnd.dart',[
'rdz']='application/vnd.data-vision.rdz',['debian.binary-package']=
' .debian.binary-package',['uvf']='application/vnd.dece.data',['uvvf']=
'application/vnd.dece.data',['uvd']='application/vnd.dece.data',['uvvd']=
'application/vnd.dece.data',['uvt']='application/vnd.dece.ttml+xml',['uvvt']=
'application/vnd.dece.ttml+xml',['uvx']='application/vnd.dece.unspecified',[
'uvvx']='application/vnd.dece.unspecified',['uvz']='application/vnd.dece.zip',[
'uvvz']='application/vnd.dece.zip',['fe_launch']=
'application/vnd.denovo.fcselayout-link',['desmume.movie']=' .desmume.movie',[
'dir-bi.plate-dl-nosuffix']=' .dir-bi.plate-dl-nosuffix',['dm.delegation+xml']=
' .dm.delegation+xml',['dna']='application/vnd.dna',['document+json']=
' .document+json',['mlp']='application/vnd.dolby.mlp',['dolby.mobile.1']=
' .dolby.mobile.1',['dolby.mobile.2']=' .dolby.mobile.2',[
'doremir.scorecloud-binary-document']=' .doremir.scorecloud-binary-document',[
'dpg']='application/vnd.dpgraph',['dfac']='application/vnd.dreamfactory',[
'drive+json']=' .drive+json',['kpxx']='application/vnd.ds-keypoint',['dtg.local'
]=' .dtg.local',['dtg.local.flash']=' .dtg.local.flash',['dtg.local.html']=
' .dtg.local.html',['ait']='application/vnd.dvb.ait',['dvb.dvbj']=' .dvb.dvbj',[
'dvb.esgcontainer']=' .dvb.esgcontainer',['dvb.ipdcdftnotifaccess']=
' .dvb.ipdcdftnotifaccess',['dvb.ipdcesgaccess']=' .dvb.ipdcesgaccess',[
'dvb.ipdcesgaccess2']=' .dvb.ipdcesgaccess2',['dvb.ipdcesgpdd']=
' .dvb.ipdcesgpdd',['dvb.ipdcroaming']=' .dvb.ipdcroaming',[
'dvb.iptv.alfec-base']=' .dvb.iptv.alfec-base',['dvb.iptv.alfec-enhancement']=
' .dvb.iptv.alfec-enhancement',['dvb.notif-aggregate-root+xml']=
' .dvb.notif-aggregate-root+xml',['dvb.notif-container+xml']=
' .dvb.notif-container+xml',['dvb.notif-generic+xml']=' .dvb.notif-generic+xml',
['dvb.notif-ia-msglist+xml']=' .dvb.notif-ia-msglist+xml',[
'dvb.notif-ia-registration-request+xml']=
' .dvb.notif-ia-registration-request+xml',[
'dvb.notif-ia-registration-response+xml']=
' .dvb.notif-ia-registration-response+xml',['dvb.notif-init+xml']=
' .dvb.notif-init+xml',['dvb.pfr']=' .dvb.pfr',['svc']=
'application/vnd.dvb.service',['geo']='application/vnd.dynageo',['dzr']=' .dzr',
['easykaraoke.cdgdownload']=' .easykaraoke.cdgdownload',['ecdis-update']=
' .ecdis-update',['mag']='application/vnd.ecowin.chart',['ecowin.filerequest']=
' .ecowin.filerequest',['ecowin.fileupdate']=' .ecowin.fileupdate',[
'ecowin.series']=' .ecowin.series',['ecowin.seriesrequest']=
' .ecowin.seriesrequest',['ecowin.seriesupdate']=' .ecowin.seriesupdate',[
'emclient.accessrequest+xml']=' .emclient.accessrequest+xml',['nml']=
'application/vnd.enliven',['enphase.envoy']=' .enphase.envoy',[
'eprints.data+xml']=' .eprints.data+xml',['esf']='application/vnd.epson.esf',[
'msf']='application/vnd.epson.msf',['qam']='application/vnd.epson.quickanime',[
'slt']='application/vnd.epson.salt',['ssf']='application/vnd.epson.ssf',[
'ericsson.quickcall']=' .ericsson.quickcall',['es3']=
'application/vnd.eszigno3+xml',['et3']='application/vnd.eszigno3+xml',[
'etsi.aoc+xml']=' .etsi.aoc+xml',['etsi.asic-e+zip']=' .etsi.asic-e+zip',[
'etsi.asic-s+zip']=' .etsi.asic-s+zip',['etsi.cug+xml']=' .etsi.cug+xml',[
'etsi.iptvcommand+xml']=' .etsi.iptvcommand+xml',['etsi.iptvdiscovery+xml']=
' .etsi.iptvdiscovery+xml',['etsi.iptvprofile+xml']=' .etsi.iptvprofile+xml',[
'etsi.iptvsad-bc+xml']=' .etsi.iptvsad-bc+xml',['etsi.iptvsad-cod+xml']=
' .etsi.iptvsad-cod+xml',['etsi.iptvsad-npvr+xml']=' .etsi.iptvsad-npvr+xml',[
'etsi.iptvservice+xml']=' .etsi.iptvservice+xml',['etsi.iptvsync+xml']=
' .etsi.iptvsync+xml',['etsi.iptvueprofile+xml']=' .etsi.iptvueprofile+xml',[
'etsi.mcid+xml']=' .etsi.mcid+xml',['etsi.mheg5']=' .etsi.mheg5',[
'etsi.overload-control-policy-dataset+xml']=
' .etsi.overload-control-policy-dataset+xml',['etsi.pstn+xml']=' .etsi.pstn+xml'
,['etsi.sci+xml']=' .etsi.sci+xml',['etsi.simservs+xml']=' .etsi.simservs+xml',[
'etsi.timestamp-token']=' .etsi.timestamp-token',['etsi.tsl+xml']=
' .etsi.tsl+xml',['etsi.tsl.der']=' .etsi.tsl.der',['eudora.data']=
' .eudora.data',['ez2']='application/vnd.ezpix-album',['ez3']=
'application/vnd.ezpix-package',['f-secure.mobile']=' .f-secure.mobile',[
'fastcopy-disk-image']=' .fastcopy-disk-image',['fdf']='application/vnd.fdf',[
'mseed']='application/vnd.fdsn.mseed',['seed']='application/vnd.fdsn.seed',[
'dataless']='application/vnd.fdsn.seed',['ffsns']=' .ffsns',['filmit.zfc']=
' .filmit.zfc',['fints']=' .fints',['firemonkeys.cloudcell']=
' .firemonkeys.cloudcell',['gph']='application/vnd.flographit',['ftc']=
'application/vnd.fluxtime.clip',['font-fontforge-sfd']=' .font-fontforge-sfd',[
'fm']='application/vnd.framemaker',['frame']='application/vnd.framemaker',[
'maker']='application/vnd.framemaker',['book']='application/vnd.framemaker',[
'fnc']='application/vnd.frogans.fnc',['ltf']='application/vnd.frogans.ltf',[
'fsc']='application/vnd.fsc.weblaunch',['oas']='application/vnd.fujitsu.oasys',[
'oa2']='application/vnd.fujitsu.oasys2',['oa3']='application/vnd.fujitsu.oasys3'
,['fg5']='application/vnd.fujitsu.oasysgp',['bh2']=
'application/vnd.fujitsu.oasysprs',['fujixerox.art-ex']=' .fujixerox.art-ex',[
'fujixerox.art4']=' .fujixerox.art4',['ddd']='application/vnd.fujixerox.ddd',[
'xdw']='application/vnd.fujixerox.docuworks',['xbd']=
'application/vnd.fujixerox.docuworks.binder',['fujixerox.docuworks.container']=
' .fujixerox.docuworks.container',['fujixerox.hbpl']=' .fujixerox.hbpl',[
'fut-misnet']=' .fut-misnet',['fzs']='application/vnd.fuzzysheet',['txd']=
'application/vnd.genomatix.tuxedo',['geo+json']=' .geo+json',['geocube+xml']=
' .geocube+xml',['ggb']='application/vnd.geogebra.file',['ggt']=
'application/vnd.geogebra.tool',['gex']='application/vnd.geometry-explorer',[
'gre']='application/vnd.geometry-explorer',['gxt']='application/vnd.geonext',[
'g2w']='application/vnd.geoplan',['g3w']='application/vnd.geospace',['gerber']=
' .gerber',['globalplatform.card-content-mgt']=
' .globalplatform.card-content-mgt',['globalplatform.card-content-mgt-response']
=' .globalplatform.card-content-mgt-response',['gmx']='application/vnd.gmx',[
'kml']='application/vnd.google-earth.kml+xml',['kmz']=
'application/vnd.google-earth.kmz',['gov.sk.e-form+xml']=' .gov.sk.e-form+xml',[
'gov.sk.e-form+zip']=' .gov.sk.e-form+zip',['gov.sk.xmldatacontainer+xml']=
' .gov.sk.xmldatacontainer+xml',['gqf']='application/vnd.grafeq',['gqs']=
'application/vnd.grafeq',['gridmp']=' .gridmp',['gac']=
'application/vnd.groove-account',['ghf']='application/vnd.groove-help',['gim']=
'application/vnd.groove-identity-message',['grv']=
'application/vnd.groove-injector',['gtm']='application/vnd.groove-tool-message',
['tpl']='application/vnd.groove-tool-template',['vcg']=
'application/vnd.groove-vcard',['hal+json']=' .hal+json',['hal']=
'application/vnd.hal+xml',['zmm']='application/vnd.handheld-entertainment+xml',[
'hbci']='application/vnd.hbci',['hcl-bireports']=' .hcl-bireports',['hdt']=
' .hdt',['heroku+json']=' .heroku+json',['les']=
'application/vnd.hhe.lesson-player',['hpgl']='application/vnd.hp-hpgl',['hpid']=
'application/vnd.hp-hpid',['hps']='application/vnd.hp-hps',['jlt']=
'application/vnd.hp-jlyt',['pcl']='application/vnd.hp-pcl',['pclxl']=
'application/vnd.hp-pclxl',['httphone']=' .httphone',['sfd-hdstx']=
'application/vnd.hydrostatix.sof-data',['hyperdrive+json']=' .hyperdrive+json',[
'hzn-3d-crossword']=' .hzn-3d-crossword',['ibm.afplinedata']=' .ibm.afplinedata'
,['ibm.electronic-media']=' .ibm.electronic-media',['mpy']=
'application/vnd.ibm.minipay',['afp']='application/vnd.ibm.modcap',['listafp']=
'application/vnd.ibm.modcap',['list3820']='application/vnd.ibm.modcap',['irm']=
'application/vnd.ibm.rights-management',['sc']=
'application/vnd.ibm.secure-container',['icc']='application/vnd.iccprofile',[
'icm']='application/vnd.iccprofile',['ieee.1905']=' .ieee.1905',['igl']=
'application/vnd.igloader',['ivp']='application/vnd.immervision-ivp',['ivu']=
'application/vnd.immervision-ivu',['ims.imsccv1p1']=' .ims.imsccv1p1',[
'ims.imsccv1p2']=' .ims.imsccv1p2',['ims.imsccv1p3']=' .ims.imsccv1p3',[
'ims.lis.v2.result+json']=' .ims.lis.v2.result+json',[
'ims.lti.v2.toolconsumerprofile+json']=' .ims.lti.v2.toolconsumerprofile+json',[
'ims.lti.v2.toolproxy+json']=' .ims.lti.v2.toolproxy+json',[
'ims.lti.v2.toolproxy.id+json']=' .ims.lti.v2.toolproxy.id+json',[
'ims.lti.v2.toolsettings+json']=' .ims.lti.v2.toolsettings+json',[
'ims.lti.v2.toolsettings.simple+json']=' .ims.lti.v2.toolsettings.simple+json',[
'informedcontrol.rms+xml']=' .informedcontrol.rms+xml',['informix-visionary']=
' .informix-visionary',['infotech.project']=' .infotech.project',[
'infotech.project+xml']=' .infotech.project+xml',['innopath.wamp.notification']=
' .innopath.wamp.notification',['igm']='application/vnd.insors.igm',['xpw']=
'application/vnd.intercon.formnet',['xpx']='application/vnd.intercon.formnet',[
'i2g']='application/vnd.intergeo',['intertrust.digibox']=' .intertrust.digibox',
['intertrust.nncp']=' .intertrust.nncp',['qbo']='application/vnd.intu.qbo',[
'qfx']='application/vnd.intu.qfx',['iptc.g2.catalogitem+xml']=
' .iptc.g2.catalogitem+xml',['iptc.g2.conceptitem+xml']=
' .iptc.g2.conceptitem+xml',['iptc.g2.knowledgeitem+xml']=
' .iptc.g2.knowledgeitem+xml',['iptc.g2.newsitem+xml']=' .iptc.g2.newsitem+xml',
['iptc.g2.newsmessage+xml']=' .iptc.g2.newsmessage+xml',[
'iptc.g2.packageitem+xml']=' .iptc.g2.packageitem+xml',[
'iptc.g2.planningitem+xml']=' .iptc.g2.planningitem+xml',['rcprofile']=
'application/vnd.ipunplugged.rcprofile',['irp']=
'application/vnd.irepository.package+xml',['xpr']='application/vnd.is-xpr',[
'fcs']='application/vnd.isac.fcs',['jam']='application/vnd.jam',[
'japannet-directory-service']=' .japannet-directory-service',[
'japannet-jpnstore-wakeup']=' .japannet-jpnstore-wakeup',[
'japannet-payment-wakeup']=' .japannet-payment-wakeup',['japannet-registration']
=' .japannet-registration',['japannet-registration-wakeup']=
' .japannet-registration-wakeup',['japannet-setstore-wakeup']=
' .japannet-setstore-wakeup',['japannet-verification']=' .japannet-verification'
,['japannet-verification-wakeup']=' .japannet-verification-wakeup',['rms']=
'application/vnd.jcp.javame.midlet-rms',['jisp']='application/vnd.jisp',['joda']
='application/vnd.joost.joda-archive',['jsk.isdn-ngn']=' .jsk.isdn-ngn',['ktz']=
'application/vnd.kahootz',['ktr']='application/vnd.kahootz',['karbon']=
'application/vnd.kde.karbon',['chrt']='application/vnd.kde.kchart',['kfo']=
'application/vnd.kde.kformula',['flw']='application/vnd.kde.kivio',['kon']=
'application/vnd.kde.kontour',['kpr']='application/vnd.kde.kpresenter',['kpt']=
'application/vnd.kde.kpresenter',['ksp']='application/vnd.kde.kspread',['kwd']=
'application/vnd.kde.kword',['kwt']='application/vnd.kde.kword',['htke']=
'application/vnd.kenameaapp',['kia']='application/vnd.kidspiration',['kne']=
'application/vnd.kinar',['knp']='application/vnd.kinar',['skp']=
'application/vnd.koan',['skd']='application/vnd.koan',['skt']=
'application/vnd.koan',['skm']='application/vnd.koan',['sse']=
'application/vnd.kodak-descriptor',['lasxml']='application/vnd.las.las+xml',[
'liberty-request+xml']=' .liberty-request+xml',['lbd']=
'application/vnd.llamagraphics.life-balance.desktop',['lbe']=
'application/vnd.llamagraphics.life-balance.exchange+xml',['123']=
'application/vnd.lotus-1-2-3',['apr']='application/vnd.lotus-approach',['pre']=
'application/vnd.lotus-freelance',['nsf']='application/vnd.lotus-notes',['org']=
'application/vnd.lotus-organizer',['scm']='application/vnd.lotus-screencam',[
'lwp']='application/vnd.lotus-wordpro',['portpkg']=
'application/vnd.macports.portpkg',['mapbox-vector-tile']=' .mapbox-vector-tile'
,['marlin.drm.actiontoken+xml']=' .marlin.drm.actiontoken+xml',[
'marlin.drm.conftoken+xml']=' .marlin.drm.conftoken+xml',[
'marlin.drm.license+xml']=' .marlin.drm.license+xml',['marlin.drm.mdcf']=
' .marlin.drm.mdcf',['mason+json']=' .mason+json',['maxmind.maxmind-db']=
' .maxmind.maxmind-db',['mcd']='application/vnd.mcd',['mc1']=
'application/vnd.medcalcdata',['cdkey']='application/vnd.mediastation.cdkey',[
'meridian-slingshot']=' .meridian-slingshot',['mwf']='application/vnd.mfer',[
'mfm']='application/vnd.mfmp',['micro+json']=' .micro+json',['flo']=
'application/vnd.micrografx.flo',['igx']='application/vnd.micrografx.igx',[
'microsoft.portable-executable']=' .microsoft.portable-executable',['miele+json'
]=' .miele+json',['mif']='application/vnd.mif',['minisoft-hp3000-save']=
' .minisoft-hp3000-save',['mitsubishi.misty-guard.trustweb']=
' .mitsubishi.misty-guard.trustweb',['daf']='application/vnd.mobius.daf',['dis']
='application/vnd.mobius.dis',['mbk']='application/vnd.mobius.mbk',['mqy']=
'application/vnd.mobius.mqy',['msl']='application/vnd.mobius.msl',['plc']=
'application/vnd.mobius.plc',['txf']='application/vnd.mobius.txf',['mpn']=
'application/vnd.mophun.application',['mpc']=
'application/vnd.mophun.certificate',['motorola.flexsuite']=
' .motorola.flexsuite',['motorola.flexsuite.adsi']=' .motorola.flexsuite.adsi',[
'motorola.flexsuite.fis']=' .motorola.flexsuite.fis',['motorola.flexsuite.gotap'
]=' .motorola.flexsuite.gotap',['motorola.flexsuite.kmr']=
' .motorola.flexsuite.kmr',['motorola.flexsuite.ttc']=' .motorola.flexsuite.ttc'
,['motorola.flexsuite.wem']=' .motorola.flexsuite.wem',['motorola.iprm']=
' .motorola.iprm',['xul']='application/vnd.mozilla.xul+xml',['ms-3mfdocument']=
' .ms-3mfdocument',['cil']='application/vnd.ms-artgalry',['ms-asf']=' .ms-asf',[
'cab']='application/vnd.ms-cab-compressed',['ms-color.iccprofile']=
' .ms-color.iccprofile',['xls']='application/vnd.ms-excel',['xlm']=
'application/vnd.ms-excel',['xla']='application/vnd.ms-excel',['xlc']=
'application/vnd.ms-excel',['xlt']='application/vnd.ms-excel',['xlw']=
'application/vnd.ms-excel',['xlam']=
'application/vnd.ms-excel.addin.macroenabled.12',['xlsb']=
'application/vnd.ms-excel.sheet.binary.macroenabled.12',['xlsm']=
'application/vnd.ms-excel.sheet.macroenabled.12',['xltm']=
'application/vnd.ms-excel.template.macroenabled.12',['eot']=
'application/vnd.ms-fontobject',['chm']='application/vnd.ms-htmlhelp',['ims']=
'application/vnd.ms-ims',['lrm']='application/vnd.ms-lrm',[
'ms-office.activex+xml']=' .ms-office.activex+xml',['thmx']=
'application/vnd.ms-officetheme',['ms-opentype']=' .ms-opentype',[
'ms-package.obfuscated-opentype']=' .ms-package.obfuscated-opentype',['cat']=
'application/vnd.ms-pki.seccat',['stl']='application/vnd.ms-pki.stl',[
'ms-playready.initiator+xml']=' .ms-playready.initiator+xml',['ppt']=
'application/vnd.ms-powerpoint',['pps']='application/vnd.ms-powerpoint',['pot']=
'application/vnd.ms-powerpoint',['ppam']=
'application/vnd.ms-powerpoint.addin.macroenabled.12',['pptm']=
'application/vnd.ms-powerpoint.presentation.macroenabled.12',['sldm']=
'application/vnd.ms-powerpoint.slide.macroenabled.12',['ppsm']=
'application/vnd.ms-powerpoint.slideshow.macroenabled.12',['potm']=
'application/vnd.ms-powerpoint.template.macroenabled.12',[
'ms-printdevicecapabilities+xml']=' .ms-printdevicecapabilities+xml',[
'ms-printing.printticket+xml']=' .ms-printing.printticket+xml',[
'ms-printschematicket+xml']=' .ms-printschematicket+xml',['mpp']=
'application/vnd.ms-project',['mpt']='application/vnd.ms-project',['ms-tnef']=
' .ms-tnef',['ms-windows.devicepairing']=' .ms-windows.devicepairing',[
'ms-windows.nwprinting.oob']=' .ms-windows.nwprinting.oob',[
'ms-windows.printerpairing']=' .ms-windows.printerpairing',['ms-windows.wsd.oob'
]=' .ms-windows.wsd.oob',['ms-wmdrm.lic-chlg-req']=' .ms-wmdrm.lic-chlg-req',[
'ms-wmdrm.lic-resp']=' .ms-wmdrm.lic-resp',['ms-wmdrm.meter-chlg-req']=
' .ms-wmdrm.meter-chlg-req',['ms-wmdrm.meter-resp']=' .ms-wmdrm.meter-resp',[
'docm']='application/vnd.ms-word.document.macroenabled.12',['dotm']=
'application/vnd.ms-word.template.macroenabled.12',['wps']=
'application/vnd.ms-works',['wks']='application/vnd.ms-works',['wcm']=
'application/vnd.ms-works',['wdb']='application/vnd.ms-works',['wpl']=
'application/vnd.ms-wpl',['xps']='application/vnd.ms-xpsdocument',[
'msa-disk-image']=' .msa-disk-image',['mseq']='application/vnd.mseq',['msign']=
' .msign',['multiad.creator']=' .multiad.creator',['multiad.creator.cif']=
' .multiad.creator.cif',['music-niff']=' .music-niff',['mus']=
'application/vnd.musician',['msty']='application/vnd.muvee.style',['taglet']=
'application/vnd.mynfc',['ncd.control']=' .ncd.control',['ncd.reference']=
' .ncd.reference',['nervana']=' .nervana',['netfpx']=' .netfpx',['nlu']=
'application/vnd.neurolanguage.nlu',['nintendo.nitro.rom']=
' .nintendo.nitro.rom',['nintendo.snes.rom']=' .nintendo.snes.rom',['ntf']=
'application/vnd.nitf',['nitf']='application/vnd.nitf',['nnd']=
'application/vnd.noblenet-directory',['nns']='application/vnd.noblenet-sealer',[
'nnw']='application/vnd.noblenet-web',['nokia.catalogs']=' .nokia.catalogs',[
'nokia.conml+wbxml']=' .nokia.conml+wbxml',['nokia.conml+xml']=
' .nokia.conml+xml',['nokia.iptv.config+xml']=' .nokia.iptv.config+xml',[
'nokia.isds-radio-presets']=' .nokia.isds-radio-presets',['nokia.landmark+wbxml'
]=' .nokia.landmark+wbxml',['nokia.landmark+xml']=' .nokia.landmark+xml',[
'nokia.landmarkcollection+xml']=' .nokia.landmarkcollection+xml',[
'nokia.n-gage.ac+xml']=' .nokia.n-gage.ac+xml',['ngdat']=
'application/vnd.nokia.n-gage.data',['n-gage']=
'application/vnd.nokia.n-gage.symbian.install',['nokia.ncd']=' .nokia.ncd',[
'nokia.pcd+wbxml']=' .nokia.pcd+wbxml',['nokia.pcd+xml']=' .nokia.pcd+xml',[
'rpst']='application/vnd.nokia.radio-preset',['rpss']=
'application/vnd.nokia.radio-presets',['edm']='application/vnd.novadigm.edm',[
'edx']='application/vnd.novadigm.edx',['ext']='application/vnd.novadigm.ext',[
'ntt-local.content-share']=' .ntt-local.content-share',[
'ntt-local.file-transfer']=' .ntt-local.file-transfer',[
'ntt-local.ogw_remote-access']=' .ntt-local.ogw_remote-access',[
'ntt-local.sip-ta_remote']=' .ntt-local.sip-ta_remote',[
'ntt-local.sip-ta_tcp_stream']=' .ntt-local.sip-ta_tcp_stream',['odc']=
'application/vnd.oasis.opendocument.chart',['otc']=
'application/vnd.oasis.opendocument.chart-template',['odb']=
'application/vnd.oasis.opendocument.database',['odf']=
'application/vnd.oasis.opendocument.formula',['odft']=
'application/vnd.oasis.opendocument.formula-template',['odg']=
'application/vnd.oasis.opendocument.graphics',['otg']=
'application/vnd.oasis.opendocument.graphics-template',['odi']=
'application/vnd.oasis.opendocument.image',['oti']=
'application/vnd.oasis.opendocument.image-template',['odp']=
'application/vnd.oasis.opendocument.presentation',['otp']=
'application/vnd.oasis.opendocument.presentation-template',['ods']=
'application/vnd.oasis.opendocument.spreadsheet',['ots']=
'application/vnd.oasis.opendocument.spreadsheet-template',['odt']=
'application/vnd.oasis.opendocument.text',['odm']=
'application/vnd.oasis.opendocument.text-master',['ott']=
'application/vnd.oasis.opendocument.text-template',['oth']=
'application/vnd.oasis.opendocument.text-web',['obn']=' .obn',['oftn.l10n+json']
=' .oftn.l10n+json',['oipf.contentaccessdownload+xml']=
' .oipf.contentaccessdownload+xml',['oipf.contentaccessstreaming+xml']=
' .oipf.contentaccessstreaming+xml',['oipf.cspg-hexbinary']=
' .oipf.cspg-hexbinary',['oipf.dae.svg+xml']=' .oipf.dae.svg+xml',[
'oipf.dae.xhtml+xml']=' .oipf.dae.xhtml+xml',['oipf.mippvcontrolmessage+xml']=
' .oipf.mippvcontrolmessage+xml',['oipf.pae.gem']=' .oipf.pae.gem',[
'oipf.spdiscovery+xml']=' .oipf.spdiscovery+xml',['oipf.spdlist+xml']=
' .oipf.spdlist+xml',['oipf.ueprofile+xml']=' .oipf.ueprofile+xml',[
'oipf.userprofile+xml']=' .oipf.userprofile+xml',['xo']=
'application/vnd.olpc-sugar',['oma-scws-config']=' .oma-scws-config',[
'oma-scws-http-request']=' .oma-scws-http-request',['oma-scws-http-response']=
' .oma-scws-http-response',['oma.bcast.associated-procedure-parameter+xml']=
' .oma.bcast.associated-procedure-parameter+xml',['oma.bcast.drm-trigger+xml']=
' .oma.bcast.drm-trigger+xml',['oma.bcast.imd+xml']=' .oma.bcast.imd+xml',[
'oma.bcast.ltkm']=' .oma.bcast.ltkm',['oma.bcast.notification+xml']=
' .oma.bcast.notification+xml',['oma.bcast.provisioningtrigger']=
' .oma.bcast.provisioningtrigger',['oma.bcast.sgboot']=' .oma.bcast.sgboot',[
'oma.bcast.sgdd+xml']=' .oma.bcast.sgdd+xml',['oma.bcast.sgdu']=
' .oma.bcast.sgdu',['oma.bcast.simple-symbol-container']=
' .oma.bcast.simple-symbol-container',['oma.bcast.smartcard-trigger+xml']=
' .oma.bcast.smartcard-trigger+xml',['oma.bcast.sprov+xml']=
' .oma.bcast.sprov+xml',['oma.bcast.stkm']=' .oma.bcast.stkm',[
'oma.cab-address-book+xml']=' .oma.cab-address-book+xml',[
'oma.cab-feature-handler+xml']=' .oma.cab-feature-handler+xml',[
'oma.cab-pcc+xml']=' .oma.cab-pcc+xml',['oma.cab-subs-invite+xml']=
' .oma.cab-subs-invite+xml',['oma.cab-user-prefs+xml']=
' .oma.cab-user-prefs+xml',['oma.dcd']=' .oma.dcd',['oma.dcdc']=' .oma.dcdc',[
'dd2']='application/vnd.oma.dd2+xml',['oma.drm.risd+xml']=' .oma.drm.risd+xml',[
'oma.group-usage-list+xml']=' .oma.group-usage-list+xml',['oma.lwm2m+json']=
' .oma.lwm2m+json',['oma.lwm2m+tlv']=' .oma.lwm2m+tlv',['oma.pal+xml']=
' .oma.pal+xml',['oma.poc.detailed-progress-report+xml']=
' .oma.poc.detailed-progress-report+xml',['oma.poc.final-report+xml']=
' .oma.poc.final-report+xml',['oma.poc.groups+xml']=' .oma.poc.groups+xml',[
'oma.poc.invocation-descriptor+xml']=' .oma.poc.invocation-descriptor+xml',[
'oma.poc.optimized-progress-report+xml']=
' .oma.poc.optimized-progress-report+xml',['oma.push']=' .oma.push',[
'oma.scidm.messages+xml']=' .oma.scidm.messages+xml',['oma.xcap-directory+xml']=
' .oma.xcap-directory+xml',['omads-email+xml']=' .omads-email+xml',[
'omads-file+xml']=' .omads-file+xml',['omads-folder+xml']=' .omads-folder+xml',[
'omaloc-supl-init']=' .omaloc-supl-init',['onepager']=' .onepager',[
'openblox.game+xml']=' .openblox.game+xml',['openblox.game-binary']=
' .openblox.game-binary',['openeye.oeb']=' .openeye.oeb',['oxt']=
'application/vnd.openofficeorg.extension',[
'openxmlformats-officedocument.custom-properties+xml']=
' .openxmlformats-officedocument.custom-properties+xml',[
'openxmlformats-officedocument.customxmlproperties+xml']=
' .openxmlformats-officedocument.customxmlproperties+xml',[
'openxmlformats-officedocument.drawing+xml']=
' .openxmlformats-officedocument.drawing+xml',[
'openxmlformats-officedocument.drawingml.chart+xml']=
' .openxmlformats-officedocument.drawingml.chart+xml',[
'openxmlformats-officedocument.drawingml.chartshapes+xml']=
' .openxmlformats-officedocument.drawingml.chartshapes+xml',[
'openxmlformats-officedocument.drawingml.diagramcolors+xml']=
' .openxmlformats-officedocument.drawingml.diagramcolors+xml',[
'openxmlformats-officedocument.drawingml.diagramdata+xml']=
' .openxmlformats-officedocument.drawingml.diagramdata+xml',[
'openxmlformats-officedocument.drawingml.diagramlayout+xml']=
' .openxmlformats-officedocument.drawingml.diagramlayout+xml',[
'openxmlformats-officedocument.drawingml.diagramstyle+xml']=
' .openxmlformats-officedocument.drawingml.diagramstyle+xml',[
'openxmlformats-officedocument.extended-properties+xml']=
' .openxmlformats-officedocument.extended-properties+xml',[
[[openxmlformats-officedocument.presentationml.commentauthors+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.commentauthors+xml]],[
'openxmlformats-officedocument.presentationml.comments+xml']=
' .openxmlformats-officedocument.presentationml.comments+xml',[
[[openxmlformats-officedocument.presentationml.handoutmaster+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.handoutmaster+xml]],[
[[openxmlformats-officedocument.presentationml.notesmaster+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.notesmaster+xml]],[
'openxmlformats-officedocument.presentationml.notesslide+xml']=
[[ .openxmlformats-officedocument.presentationml.notesslide+xml]],['pptx']=
[[application/vnd.openxmlformats-officedocument.presentationml.presentation]],[
[[openxmlformats-officedocument.presentationml.presentation.main+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.presentation.main+xml]],[
'openxmlformats-officedocument.presentationml.presprops+xml']=
[[ .openxmlformats-officedocument.presentationml.presprops+xml]],['sldx']=
[[application/vnd.openxmlformats-officedocument.presentationml.slide]],[
'openxmlformats-officedocument.presentationml.slide+xml']=
' .openxmlformats-officedocument.presentationml.slide+xml',[
[[openxmlformats-officedocument.presentationml.slidelayout+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.slidelayout+xml]],[
[[openxmlformats-officedocument.presentationml.slidemaster+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.slidemaster+xml]],['ppsx']=
[[application/vnd.openxmlformats-officedocument.presentationml.slideshow]],[
[[openxmlformats-officedocument.presentationml.slideshow.main+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.slideshow.main+xml]],[
[[openxmlformats-officedocument.presentationml.slideupdateinfo+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.slideupdateinfo+xml]],[
[[openxmlformats-officedocument.presentationml.tablestyles+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.tablestyles+xml]],[
'openxmlformats-officedocument.presentationml.tags+xml']=
' .openxmlformats-officedocument.presentationml.tags+xml',['potx']=
[[application/vnd.openxmlformats-officedocument.presentationml.template]],[
[[openxmlformats-officedocument.presentationml.template.main+xml]] ]=
[[ .openxmlformats-officedocument.presentationml.template.main+xml]],[
'openxmlformats-officedocument.presentationml.viewprops+xml']=
[[ .openxmlformats-officedocument.presentationml.viewprops+xml]],[
'openxmlformats-officedocument.spreadsheetml.calcchain+xml']=
' .openxmlformats-officedocument.spreadsheetml.calcchain+xml',[
'openxmlformats-officedocument.spreadsheetml.chartsheet+xml']=
[[ .openxmlformats-officedocument.spreadsheetml.chartsheet+xml]],[
'openxmlformats-officedocument.spreadsheetml.comments+xml']=
' .openxmlformats-officedocument.spreadsheetml.comments+xml',[
'openxmlformats-officedocument.spreadsheetml.connections+xml']=
[[ .openxmlformats-officedocument.spreadsheetml.connections+xml]],[
'openxmlformats-officedocument.spreadsheetml.dialogsheet+xml']=
[[ .openxmlformats-officedocument.spreadsheetml.dialogsheet+xml]],[
[[openxmlformats-officedocument.spreadsheetml.externallink+xml]] ]=
[[ .openxmlformats-officedocument.spreadsheetml.externallink+xml]],[
[[openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml]] ]=
[[ .openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml]],[
[[openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml]] ]=
[[ .openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml]],[
'openxmlformats-officedocument.spreadsheetml.pivottable+xml']=
[[ .openxmlformats-officedocument.spreadsheetml.pivottable+xml]],[
'openxmlformats-officedocument.spreadsheetml.querytable+xml']=
[[ .openxmlformats-officedocument.spreadsheetml.querytable+xml]],[
[[openxmlformats-officedocument.spreadsheetml.revisionheaders+xml]] ]=
[[ .openxmlformats-officedocument.spreadsheetml.revisionheaders+xml]],[
'openxmlformats-officedocument.spreadsheetml.revisionlog+xml']=
[[ .openxmlformats-officedocument.spreadsheetml.revisionlog+xml]],[
[[openxmlformats-officedocument.spreadsheetml.sharedstrings+xml]] ]=
[[ .openxmlformats-officedocument.spreadsheetml.sharedstrings+xml]],['xlsx']=
[[application/vnd.openxmlformats-officedocument.spreadsheetml.sheet]],[
'openxmlformats-officedocument.spreadsheetml.sheet.main+xml']=
[[ .openxmlformats-officedocument.spreadsheetml.sheet.main+xml]],[
[[openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml]] ]=
[[ .openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml]],[
'openxmlformats-officedocument.spreadsheetml.styles+xml']=
' .openxmlformats-officedocument.spreadsheetml.styles+xml',[
'openxmlformats-officedocument.spreadsheetml.table+xml']=
' .openxmlformats-officedocument.spreadsheetml.table+xml',[
[[openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml]] ]=
[[ .openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml]],['xltx']=
[[application/vnd.openxmlformats-officedocument.spreadsheetml.template]],[
[[openxmlformats-officedocument.spreadsheetml.template.main+xml]] ]=
[[ .openxmlformats-officedocument.spreadsheetml.template.main+xml]],[
'openxmlformats-officedocument.spreadsheetml.usernames+xml']=
' .openxmlformats-officedocument.spreadsheetml.usernames+xml',[
[[openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml]] ]=
[[ .openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml]],[
'openxmlformats-officedocument.spreadsheetml.worksheet+xml']=
' .openxmlformats-officedocument.spreadsheetml.worksheet+xml',[
'openxmlformats-officedocument.theme+xml']=
' .openxmlformats-officedocument.theme+xml',[
'openxmlformats-officedocument.themeoverride+xml']=
' .openxmlformats-officedocument.themeoverride+xml',[
'openxmlformats-officedocument.vmldrawing']=
' .openxmlformats-officedocument.vmldrawing',[
'openxmlformats-officedocument.wordprocessingml.comments+xml']=
[[ .openxmlformats-officedocument.wordprocessingml.comments+xml]],['docx']=
[[application/vnd.openxmlformats-officedocument.wordprocessingml.document]],[
[[openxmlformats-officedocument.wordprocessingml.document.glossary+xml]] ]=
[[ .openxmlformats-officedocument.wordprocessingml.document.glossary+xml]],[
[[openxmlformats-officedocument.wordprocessingml.document.main+xml]] ]=
[[ .openxmlformats-officedocument.wordprocessingml.document.main+xml]],[
'openxmlformats-officedocument.wordprocessingml.endnotes+xml']=
[[ .openxmlformats-officedocument.wordprocessingml.endnotes+xml]],[
[[openxmlformats-officedocument.wordprocessingml.fonttable+xml]] ]=
[[ .openxmlformats-officedocument.wordprocessingml.fonttable+xml]],[
'openxmlformats-officedocument.wordprocessingml.footer+xml']=
' .openxmlformats-officedocument.wordprocessingml.footer+xml',[
[[openxmlformats-officedocument.wordprocessingml.footnotes+xml]] ]=
[[ .openxmlformats-officedocument.wordprocessingml.footnotes+xml]],[
[[openxmlformats-officedocument.wordprocessingml.numbering+xml]] ]=
[[ .openxmlformats-officedocument.wordprocessingml.numbering+xml]],[
'openxmlformats-officedocument.wordprocessingml.settings+xml']=
[[ .openxmlformats-officedocument.wordprocessingml.settings+xml]],[
'openxmlformats-officedocument.wordprocessingml.styles+xml']=
' .openxmlformats-officedocument.wordprocessingml.styles+xml',['dotx']=
[[application/vnd.openxmlformats-officedocument.wordprocessingml.template]],[
[[openxmlformats-officedocument.wordprocessingml.template.main+xml]] ]=
[[ .openxmlformats-officedocument.wordprocessingml.template.main+xml]],[
[[openxmlformats-officedocument.wordprocessingml.websettings+xml]] ]=
[[ .openxmlformats-officedocument.wordprocessingml.websettings+xml]],[
'openxmlformats-package.core-properties+xml']=
' .openxmlformats-package.core-properties+xml',[
'openxmlformats-package.digital-signature-xmlsignature+xml']=
' .openxmlformats-package.digital-signature-xmlsignature+xml',[
'openxmlformats-package.relationships+xml']=
' .openxmlformats-package.relationships+xml',['oracle.resource+json']=
' .oracle.resource+json',['orange.indata']=' .orange.indata',['osa.netdeploy']=
' .osa.netdeploy',['mgp']='application/vnd.osgeo.mapguide.package',[
'osgi.bundle']=' .osgi.bundle',['dp']='application/vnd.osgi.dp',['esa']=
'application/vnd.osgi.subsystem',['otps.ct-kip+xml']=' .otps.ct-kip+xml',[
'oxli.countgraph']=' .oxli.countgraph',['pagerduty+json']=' .pagerduty+json',[
'pdb']='application/vnd.palm',['pqa']='application/vnd.palm',['oprc']=
'application/vnd.palm',['panoply']=' .panoply',['paos.xml']=' .paos.xml',['paw']
='application/vnd.pawaafile',['pcos']=' .pcos',['str']=
'application/vnd.pg.format',['ei6']='application/vnd.pg.osasli',[
'piaccess.application-licence']=' .piaccess.application-licence',['efif']=
'application/vnd.picsel',['wg']='application/vnd.pmi.widget',[
'poc.group-advertisement+xml']=' .poc.group-advertisement+xml',['plf']=
'application/vnd.pocketlearn',['pbd']='application/vnd.powerbuilder6',[
'powerbuilder6-s']=' .powerbuilder6-s',['powerbuilder7']=' .powerbuilder7',[
'powerbuilder7-s']=' .powerbuilder7-s',['powerbuilder75']=' .powerbuilder75',[
'powerbuilder75-s']=' .powerbuilder75-s',['preminet']=' .preminet',['box']=
'application/vnd.previewsystems.box',['mgz']='application/vnd.proteus.magazine',
['qps']='application/vnd.publishare-delta-tree',['ptid']=
'application/vnd.pvi.ptid1',['pwg-multiplexed']=' .pwg-multiplexed',[
'pwg-xhtml-print+xml']=' .pwg-xhtml-print+xml',['qualcomm.brew-app-res']=
' .qualcomm.brew-app-res',['quarantainenet']=' .quarantainenet',['qxd']=
'application/vnd.quark.quarkxpress',['qxt']='application/vnd.quark.quarkxpress',
['qwd']='application/vnd.quark.quarkxpress',['qwt']=
'application/vnd.quark.quarkxpress',['qxl']='application/vnd.quark.quarkxpress',
['qxb']='application/vnd.quark.quarkxpress',['quobject-quoxdocument']=
' .quobject-quoxdocument',['radisys.moml+xml']=' .radisys.moml+xml',[
'radisys.msml+xml']=' .radisys.msml+xml',['radisys.msml-audit+xml']=
' .radisys.msml-audit+xml',['radisys.msml-audit-conf+xml']=
' .radisys.msml-audit-conf+xml',['radisys.msml-audit-conn+xml']=
' .radisys.msml-audit-conn+xml',['radisys.msml-audit-dialog+xml']=
' .radisys.msml-audit-dialog+xml',['radisys.msml-audit-stream+xml']=
' .radisys.msml-audit-stream+xml',['radisys.msml-conf+xml']=
' .radisys.msml-conf+xml',['radisys.msml-dialog+xml']=
' .radisys.msml-dialog+xml',['radisys.msml-dialog-base+xml']=
' .radisys.msml-dialog-base+xml',['radisys.msml-dialog-fax-detect+xml']=
' .radisys.msml-dialog-fax-detect+xml',['radisys.msml-dialog-fax-sendrecv+xml']=
' .radisys.msml-dialog-fax-sendrecv+xml',['radisys.msml-dialog-group+xml']=
' .radisys.msml-dialog-group+xml',['radisys.msml-dialog-speech+xml']=
' .radisys.msml-dialog-speech+xml',['radisys.msml-dialog-transform+xml']=
' .radisys.msml-dialog-transform+xml',['rainstor.data']=' .rainstor.data',[
'rapid']=' .rapid',['bed']='application/vnd.realvnc.bed',['mxl']=
'application/vnd.recordare.musicxml',['musicxml']=
'application/vnd.recordare.musicxml+xml',['renlearn.rlprint']=
' .renlearn.rlprint',['cryptonote']='application/vnd.rig.cryptonote',['cod']=
'application/vnd.rim.cod',['rm']='application/vnd.rn-realmedia',['rmvb']=
'application/vnd.rn-realmedia-vbr',['link66']=
'application/vnd.route66.link66+xml',['rs-274x']=' .rs-274x',['ruckus.download']
=' .ruckus.download',['s3sms']=' .s3sms',['st']=
'application/vnd.sailingtracker.track',['sbm.cid']=' .sbm.cid',['sbm.mid2']=
' .sbm.mid2',['scribus']=' .scribus',['sealed.3df']=' .sealed.3df',['sealed.csf'
]=' .sealed.csf',['sealed.doc']=' .sealed.doc',['sealed.eml']=' .sealed.eml',[
'sealed.mht']=' .sealed.mht',['sealed.net']=' .sealed.net',['sealed.ppt']=
' .sealed.ppt',['sealed.tiff']=' .sealed.tiff',['sealed.xls']=' .sealed.xls',[
'sealedmedia.softseal.html']=' .sealedmedia.softseal.html',[
'sealedmedia.softseal.pdf']=' .sealedmedia.softseal.pdf',['see']=
'application/vnd.seemail',['sema']='application/vnd.sema',['semd']=
'application/vnd.semd',['semf']='application/vnd.semf',['ifm']=
'application/vnd.shana.informed.formdata',['itp']=
'application/vnd.shana.informed.formtemplate',['iif']=
'application/vnd.shana.informed.interchange',['ipk']=
'application/vnd.shana.informed.package',['twd']=
'application/vnd.simtech-mindmapper',['twds']=
'application/vnd.simtech-mindmapper',['siren+json']=' .siren+json',['mmf']=
'application/vnd.smaf',['smart.notebook']=' .smart.notebook',['teacher']=
'application/vnd.smart.teacher',['software602.filler.form+xml']=
' .software602.filler.form+xml',['software602.filler.form-xml-zip']=
' .software602.filler.form-xml-zip',['sdkm']='application/vnd.solent.sdkm+xml',[
'sdkd']='application/vnd.solent.sdkm+xml',['dxp']='application/vnd.spotfire.dxp'
,['sfs']='application/vnd.spotfire.sfs',['sss-cod']=' .sss-cod',['sss-dtf']=
' .sss-dtf',['sss-ntf']=' .sss-ntf',['sdc']='application/vnd.stardivision.calc',
['sda']='application/vnd.stardivision.draw',['sdd']=
'application/vnd.stardivision.impress',['smf']=
'application/vnd.stardivision.math',['sdw']=
'application/vnd.stardivision.writer',['vor']=
'application/vnd.stardivision.writer',['sgl']=
'application/vnd.stardivision.writer-global',['smzip']=
'application/vnd.stepmania.package',['sm']='application/vnd.stepmania.stepchart'
,['street-stream']=' .street-stream',['sun.wadl+xml']=' .sun.wadl+xml',['sxc']=
'application/vnd.sun.xml.calc',['stc']='application/vnd.sun.xml.calc.template',[
'sxd']='application/vnd.sun.xml.draw',['std']=
'application/vnd.sun.xml.draw.template',['sxi']=
'application/vnd.sun.xml.impress',['sti']=
'application/vnd.sun.xml.impress.template',['sxm']=
'application/vnd.sun.xml.math',['sxw']='application/vnd.sun.xml.writer',['sxg']=
'application/vnd.sun.xml.writer.global',['stw']=
'application/vnd.sun.xml.writer.template',['sus']='application/vnd.sus-calendar'
,['susp']='application/vnd.sus-calendar',['svd']='application/vnd.svd',[
'swiftview-ics']=' .swiftview-ics',['sis']='application/vnd.symbian.install',[
'sisx']='application/vnd.symbian.install',['xsm']='application/vnd.syncml+xml',[
'bdm']='application/vnd.syncml.dm+wbxml',['xdm']='application/vnd.syncml.dm+xml'
,['syncml.dm.notification']=' .syncml.dm.notification',['syncml.dmddf+wbxml']=
' .syncml.dmddf+wbxml',['syncml.dmddf+xml']=' .syncml.dmddf+xml',[
'syncml.dmtnds+wbxml']=' .syncml.dmtnds+wbxml',['syncml.dmtnds+xml']=
' .syncml.dmtnds+xml',['syncml.ds.notification']=' .syncml.ds.notification',[
'tao']='application/vnd.tao.intent-module-archive',['pcap']=
'application/vnd.tcpdump.pcap',['cap']='application/vnd.tcpdump.pcap',['dmp']=
'application/vnd.tcpdump.pcap',['tmd.mediaflex.api+xml']=
' .tmd.mediaflex.api+xml',['tml']=' .tml',['tmo']=
'application/vnd.tmobile-livetv',['tpt']='application/vnd.trid.tpt',['mxs']=
'application/vnd.triscape.mxs',['tra']='application/vnd.trueapp',['truedoc']=
' .truedoc',['ubisoft.webplayer']=' .ubisoft.webplayer',['ufd']=
'application/vnd.ufdl',['ufdl']='application/vnd.ufdl',['utz']=
'application/vnd.uiq.theme',['umj']='application/vnd.umajin',['unityweb']=
'application/vnd.unity',['uoml']='application/vnd.uoml+xml',['uplanet.alert']=
' .uplanet.alert',['uplanet.alert-wbxml']=' .uplanet.alert-wbxml',[
'uplanet.bearer-choice']=' .uplanet.bearer-choice',[
'uplanet.bearer-choice-wbxml']=' .uplanet.bearer-choice-wbxml',[
'uplanet.cacheop']=' .uplanet.cacheop',['uplanet.cacheop-wbxml']=
' .uplanet.cacheop-wbxml',['uplanet.channel']=' .uplanet.channel',[
'uplanet.channel-wbxml']=' .uplanet.channel-wbxml',['uplanet.list']=
' .uplanet.list',['uplanet.list-wbxml']=' .uplanet.list-wbxml',[
'uplanet.listcmd']=' .uplanet.listcmd',['uplanet.listcmd-wbxml']=
' .uplanet.listcmd-wbxml',['uplanet.signal']=' .uplanet.signal',['uri-map']=
' .uri-map',['valve.source.material']=' .valve.source.material',['vcx']=
'application/vnd.vcx',['vd-study']=' .vd-study',['vectorworks']=' .vectorworks',
['vel+json']=' .vel+json',['verimatrix.vcas']=' .verimatrix.vcas',[
'vidsoft.vidconference']=' .vidsoft.vidconference',['vsd']=
'application/vnd.visio',['vst']='application/vnd.visio',['vss']=
'application/vnd.visio',['vsw']='application/vnd.visio',['vis']=
'application/vnd.visionary',['vividence.scriptfile']=' .vividence.scriptfile',[
'vsf']='application/vnd.vsf',['wap.sic']=' .wap.sic',['wap.slc']=' .wap.slc',[
'wbxml']='application/vnd.wap.wbxml',['wmlc']='application/vnd.wap.wmlc',[
'wmlsc']='application/vnd.wap.wmlscriptc',['wtb']='application/vnd.webturbo',[
'wfa.p2p']=' .wfa.p2p',['windows.devicepairing']=' .windows.devicepairing',[
'wmc']=' .wmc',['wmf.bootstrap']=' .wmf.bootstrap',['wolfram.mathematica']=
' .wolfram.mathematica',['wolfram.mathematica.package']=
' .wolfram.mathematica.package',['nbp']='application/vnd.wolfram.player',['wpd']
='application/vnd.wordperfect',['wqd']='application/vnd.wqd',[
'wrq-hp3000-labelled']=' .wrq-hp3000-labelled',['stf']='application/vnd.wt.stf',
['wv.csp+wbxml']=' .wv.csp+wbxml',['wv.csp+xml']=' .wv.csp+xml',['wv.ssp+xml']=
' .wv.ssp+xml',['xacml+json']=' .xacml+json',['xar']='application/vnd.xara',[
'xfdl']='application/vnd.xfdl',['xfdl.webform']=' .xfdl.webform',['xmi+xml']=
' .xmi+xml',['xmpie.cpkg']=' .xmpie.cpkg',['xmpie.dpkg']=' .xmpie.dpkg',[
'xmpie.plan']=' .xmpie.plan',['xmpie.ppkg']=' .xmpie.ppkg',['xmpie.xlim']=
' .xmpie.xlim',['hvd']='application/vnd.yamaha.hv-dic',['hvs']=
'application/vnd.yamaha.hv-script',['hvp']='application/vnd.yamaha.hv-voice',[
'osf']='application/vnd.yamaha.openscoreformat',['osfpvg']=
'application/vnd.yamaha.openscoreformat.osfpvg+xml',['yamaha.remote-setup']=
' .yamaha.remote-setup',['saf']='application/vnd.yamaha.smaf-audio',['spf']=
'application/vnd.yamaha.smaf-phrase',['yamaha.through-ngn']=
' .yamaha.through-ngn',['yamaha.tunnel-udpencap']=' .yamaha.tunnel-udpencap',[
'yaoweme']=' .yaoweme',['cmp']='application/vnd.yellowriver-custom-menu',['zir']
='application/vnd.zul',['zirz']='application/vnd.zul',['zaz']=
'application/vnd.zzazz.deck+xml',['vxml']='application/voicexml+xml',['wgt']=
'application/widget',['hlp']='application/winhlp',['1']=' .1',['wsdl']=
'application/wsdl+xml',['wspolicy']='application/wspolicy+xml',['7z']=
'application/x-7z-compressed',['abw']='application/x-abiword',['ace']=
'application/x-ace-compressed',['dmg']='application/x-apple-diskimage',['aab']=
'application/x-authorware-bin',['x32']='application/x-authorware-bin',['u32']=
'application/x-authorware-bin',['vox']='application/x-authorware-bin',['aam']=
'application/x-authorware-map',['aas']='application/x-authorware-seg',['bcpio']=
'application/x-bcpio',['torrent']='application/x-bittorrent',['blb']=
'application/x-blorb',['blorb']='application/x-blorb',['bz']=
'application/x-bzip',['bz2']='application/x-bzip2',['boz']='application/x-bzip2'
,['cbr']='application/x-cbr',['cba']='application/x-cbr',['cbt']=
'application/x-cbr',['cbz']='application/x-cbr',['cb7']='application/x-cbr',[
'vcd']='application/x-cdlink',['cfs']='application/x-cfs-compressed',['chat']=
'application/x-chat',['pgn']='application/x-chess-pgn',['nsc']=
'application/x-conference',['cpio']='application/x-cpio',['csh']=
'application/x-csh',['deb']='application/x-debian-package',['udeb']=
'application/x-debian-package',['dgc']='application/x-dgc-compressed',['dir']=
'application/x-director',['dcr']='application/x-director',['dxr']=
'application/x-director',['cst']='application/x-director',['cct']=
'application/x-director',['cxt']='application/x-director',['w3d']=
'application/x-director',['fgd']='application/x-director',['swa']=
'application/x-director',['wad']='application/x-doom',['ncx']=
'application/x-dtbncx+xml',['dtb']='application/x-dtbook+xml',['res']=
'application/x-dtbresource+xml',['dvi']='application/x-dvi',['evy']=
'application/x-envoy',['eva']='application/x-eva',['bdf']=
'application/x-font-bdf',['gsf']='application/x-font-ghostscript',['psf']=
'application/x-font-linux-psf',['pcf']='application/x-font-pcf',['snf']=
'application/x-font-snf',['pfa']='application/x-font-type1',['pfb']=
'application/x-font-type1',['pfm']='application/x-font-type1',['afm']=
'application/x-font-type1',['arc']='application/x-freearc',['spl']=
'application/x-futuresplash',['gca']='application/x-gca-compressed',['ulx']=
'application/x-glulx',['gnumeric']='application/x-gnumeric',['gramps']=
'application/x-gramps-xml',['gtar']='application/x-gtar',['hdf']=
'application/x-hdf',['install']='application/x-install-instructions',['iso']=
'application/x-iso9660-image',['jnlp']='application/x-java-jnlp-file',['latex']=
'application/x-latex',['lzh']='application/x-lzh-compressed',['lha']=
'application/x-lzh-compressed',['mie']='application/x-mie',['prc']=
'application/x-mobipocket-ebook',['mobi']='application/x-mobipocket-ebook',[
'application']='application/x-ms-application',['lnk']=
'application/x-ms-shortcut',['wmd']='application/x-ms-wmd',['xbap']=
'application/x-ms-xbap',['mdb']='application/x-msaccess',['obd']=
'application/x-msbinder',['crd']='application/x-mscardfile',['clp']=
'application/x-msclip',['exe']='application/x-msdownload',['dll']=
'application/x-msdownload',['com']='application/x-msdownload',['bat']=
'application/x-msdownload',['msi']='application/x-msdownload',['mvb']=
'application/x-msmediaview',['m13']='application/x-msmediaview',['m14']=
'application/x-msmediaview',['wmf']='application/x-msmetafile',['wmz']=
'application/x-msmetafile',['emf']='application/x-msmetafile',['emz']=
'application/x-msmetafile',['mny']='application/x-msmoney',['pub']=
'application/x-mspublisher',['scd']='application/x-msschedule',['trm']=
'application/x-msterminal',['wri']='application/x-mswrite',['nc']=
'application/x-netcdf',['cdf']='application/x-netcdf',['nzb']=
'application/x-nzb',['p12']='application/x-pkcs12',['pfx']=
'application/x-pkcs12',['p7b']='application/x-pkcs7-certificates',['spc']=
'application/x-pkcs7-certificates',['p7r']='application/x-pkcs7-certreqresp',[
'rar']='application/x-rar-compressed',['ris']=
'application/x-research-info-systems',['sh']='application/x-sh',['shar']=
'application/x-shar',['swf']='application/x-shockwave-flash',['xap']=
'application/x-silverlight-app',['sql']='application/x-sql',['sit']=
'application/x-stuffit',['sitx']='application/x-stuffitx',['srt']=
'application/x-subrip',['sv4cpio']='application/x-sv4cpio',['sv4crc']=
'application/x-sv4crc',['t3']='application/x-t3vm-image',['gam']=
'application/x-tads',['tar']='application/x-tar',['tcl']='application/x-tcl',[
'tex']='application/x-tex',['tfm']='application/x-tex-tfm',['texinfo']=
'application/x-texinfo',['texi']='application/x-texinfo',['obj']=
'application/x-tgif',['ustar']='application/x-ustar',['src']=
'application/x-wais-source',['der']='application/x-x509-ca-cert',['crt']=
'application/x-x509-ca-cert',['fig']='application/x-xfig',['xlf']=
'application/x-xliff+xml',['xpi']='application/x-xpinstall',['xz']=
'application/x-xz',['z1']='application/x-zmachine',['z2']=
'application/x-zmachine',['z3']='application/x-zmachine',['z4']=
'application/x-zmachine',['z5']='application/x-zmachine',['z6']=
'application/x-zmachine',['z7']='application/x-zmachine',['z8']=
'application/x-zmachine',['xaml']='application/xaml+xml',['xdf']=
'application/xcap-diff+xml',['xenc']='application/xenc+xml',['xhtml']=
'application/xhtml+xml',['xht']='application/xhtml+xml',['xml']=
'application/xml',['xsl']='application/xml',['dtd']='application/xml-dtd',['xop'
]='application/xop+xml',['xpl']='application/xproc+xml',['xslt']=
'application/xslt+xml',['xspf']='application/xspf+xml',['mxml']=
'application/xv+xml',['xhvml']='application/xv+xml',['xvml']=
'application/xv+xml',['xvm']='application/xv+xml',['yang']='application/yang',[
'yin']='application/yin+xml',['zip']='application/zip',['adp']='audio/adpcm',[
'au']='audio/basic',['snd']='audio/basic',['5']=' .5',['mid']='audio/midi',[
'midi']='audio/midi',['kar']='audio/midi',['rmi']='audio/midi',['m4a']=
'audio/mp4',['mp4a']='audio/mp4',['mpga']='audio/mpeg',['mp2']='audio/mpeg',[
'mp2a']='audio/mpeg',['mp3']='audio/mpeg',['m2a']='audio/mpeg',['m3a']=
'audio/mpeg',['oga']='audio/ogg',['ogg']='audio/ogg',['spx']='audio/ogg',['s3m']
='audio/s3m',['sil']='audio/silk',['3gpp.iufp']=' .3gpp.iufp',['4sb']=' .4sb',[
'audiokoz']=' .audiokoz',['celp']=' .celp',['cisco.nse']=' .cisco.nse',[
'cmles.radio-events']=' .cmles.radio-events',['cns.anp1']=' .cns.anp1',[
'cns.inf1']=' .cns.inf1',['uva']='audio/vnd.dece.audio',['uvva']=
'audio/vnd.dece.audio',['eol']='audio/vnd.digital-winds',['dlna.adts']=
' .dlna.adts',['dolby.heaac.1']=' .dolby.heaac.1',['dolby.heaac.2']=
' .dolby.heaac.2',['dolby.mlp']=' .dolby.mlp',['dolby.mps']=' .dolby.mps',[
'dolby.pl2']=' .dolby.pl2',['dolby.pl2x']=' .dolby.pl2x',['dolby.pl2z']=
' .dolby.pl2z',['dolby.pulse.1']=' .dolby.pulse.1',['dra']='audio/vnd.dra',[
'dts']='audio/vnd.dts',['dtshd']='audio/vnd.dts.hd',['dvb.file']=' .dvb.file',[
'everad.plj']=' .everad.plj',['hns.audio']=' .hns.audio',['lvp']=
'audio/vnd.lucent.voice',['pya']='audio/vnd.ms-playready.media.pya',[
'nokia.mobile-xmf']=' .nokia.mobile-xmf',['nortel.vbk']=' .nortel.vbk',[
'ecelp4800']='audio/vnd.nuera.ecelp4800',['ecelp7470']=
'audio/vnd.nuera.ecelp7470',['ecelp9600']='audio/vnd.nuera.ecelp9600',[
'octel.sbc']=' .octel.sbc',['qcelp']=' .qcelp',['rhetorex.32kadpcm']=
' .rhetorex.32kadpcm',['rip']='audio/vnd.rip',['sealedmedia.softseal.mpeg']=
' .sealedmedia.softseal.mpeg',['vmx.cvsd']=' .vmx.cvsd',['weba']='audio/webm',[
'aac']='audio/x-aac',['aif']='audio/x-aiff',['aiff']='audio/x-aiff',['aifc']=
'audio/x-aiff',['caf']='audio/x-caf',['flac']='audio/x-flac',['mka']=
'audio/x-matroska',['m3u']='audio/x-mpegurl',['wax']='audio/x-ms-wax',['wma']=
'audio/x-ms-wma',['ram']='audio/x-pn-realaudio',['ra']='audio/x-pn-realaudio',[
'rmp']='audio/x-pn-realaudio-plugin',['wav']='audio/x-wav',['xm']='audio/xm',[
'cdx']='chemical/x-cdx',['cif']='chemical/x-cif',['cmdf']='chemical/x-cmdf',[
'cml']='chemical/x-cml',['csml']='chemical/x-csml',['xyz']='chemical/x-xyz',[
'ttc']='font/collection',['otf']='font/otf',['ttf']='font/ttf',['woff']=
'font/woff',['woff2']='font/woff2',['bmp']='image/bmp',['cgm']='image/cgm',['g3'
]='image/g3fax',['gif']='image/gif',['ief']='image/ief',['jpeg']='image/jpeg',[
'jpg']='image/jpeg',['jpe']='image/jpeg',['ktx']='image/ktx',['png']='image/png'
,['btif']='image/prs.btif',['pti']=' .pti',['sgi']='image/sgi',['svg']=
'image/svg+xml',['svgz']='image/svg+xml',['tiff']='image/tiff',['tif']=
'image/tiff',['psd']='image/vnd.adobe.photoshop',['airzip.accelerator.azv']=
' .airzip.accelerator.azv',['cns.inf2']=' .cns.inf2',['uvi']=
'image/vnd.dece.graphic',['uvvi']='image/vnd.dece.graphic',['uvg']=
'image/vnd.dece.graphic',['uvvg']='image/vnd.dece.graphic',['djvu']=
'image/vnd.djvu',['djv']='image/vnd.djvu',['dwg']='image/vnd.dwg',['dxf']=
'image/vnd.dxf',['fbs']='image/vnd.fastbidsheet',['fpx']='image/vnd.fpx',['fst']
='image/vnd.fst',['mmr']='image/vnd.fujixerox.edmics-mmr',['rlc']=
'image/vnd.fujixerox.edmics-rlc',['globalgraphics.pgb']=' .globalgraphics.pgb',[
'microsoft.icon']=' .microsoft.icon',['mix']=' .mix',['mozilla.apng']=
' .mozilla.apng',['mdi']='image/vnd.ms-modi',['wdp']='image/vnd.ms-photo',['npx'
]='image/vnd.net-fpx',['radiance']=' .radiance',['sealed.png']=' .sealed.png',[
'sealedmedia.softseal.gif']=' .sealedmedia.softseal.gif',[
'sealedmedia.softseal.jpg']=' .sealedmedia.softseal.jpg',['svf']=' .svf',[
'tencent.tap']=' .tencent.tap',['valve.source.texture']=' .valve.source.texture'
,['wbmp']='image/vnd.wap.wbmp',['xif']='image/vnd.xiff',['zbrush.pcx']=
' .zbrush.pcx',['webp']='image/webp',['3ds']='image/x-3ds',['ras']=
'image/x-cmu-raster',['cmx']='image/x-cmx',['fh']='image/x-freehand',['fhc']=
'image/x-freehand',['fh4']='image/x-freehand',['fh5']='image/x-freehand',['fh7']
='image/x-freehand',['ico']='image/x-icon',['sid']='image/x-mrsid-image',['pcx']
='image/x-pcx',['pic']='image/x-pict',['pct']='image/x-pict',['pnm']=
'image/x-portable-anymap',['pbm']='image/x-portable-bitmap',['pgm']=
'image/x-portable-graymap',['ppm']='image/x-portable-pixmap',['rgb']=
'image/x-rgb',['tga']='image/x-tga',['xbm']='image/x-xbitmap',['xpm']=
'image/x-xpixmap',['xwd']='image/x-xwindowdump',['eml']='message/rfc822',['mime'
]='message/rfc822',['si.simp']=' .si.simp',['wfa.wsc']=' .wfa.wsc',['igs']=
'model/iges',['iges']='model/iges',['msh']='model/mesh',['mesh']='model/mesh',[
'silo']='model/mesh',['dae']='model/vnd.collada+xml',['dwf']='model/vnd.dwf',[
'flatland.3dml']=' .flatland.3dml',['gdl']='model/vnd.gdl',['gs-gdl']=' .gs-gdl'
,['gs.gdl']=' .gs.gdl',['gtw']='model/vnd.gtw',['moml+xml']=' .moml+xml',['mts']
='model/vnd.mts',['opengex']=' .opengex',['parasolid.transmit.binary']=
' .parasolid.transmit.binary',['parasolid.transmit.text']=
' .parasolid.transmit.text',['rosette.annotated-data-model']=
' .rosette.annotated-data-model',['valve.source.compiled-map']=
' .valve.source.compiled-map',['vtu']='model/vnd.vtu',['wrl']='model/vrml',[
'vrml']='model/vrml',['x3db']='model/x3d+binary',['x3dbz']='model/x3d+binary',[
'x3dv']='model/x3d+vrml',['x3dvz']='model/x3d+vrml',['x3d']='model/x3d+xml',[
'x3dz']='model/x3d+xml',['appcache']='text/cache-manifest',['ics']=
'text/calendar',['ifb']='text/calendar',['css']='text/css',['csv']='text/csv',[
'html']='text/html',['htm']='text/html',['n3']='text/n3',['txt']='text/plain',[
'text']='text/plain',['conf']='text/plain',['def']='text/plain',['list']=
'text/plain',['log']='text/plain',['in']='text/plain',['fallenstein.rst']=
' .fallenstein.rst',['dsc']='text/prs.lines.tag',['prop.logic']=' .prop.logic',[
'rtx']='text/richtext',['sgml']='text/sgml',['sgm']='text/sgml',['tsv']=
'text/tab-separated-values',['t']='text/troff',['tr']='text/troff',['roff']=
'text/troff',['man']='text/troff',['me']='text/troff',['ms']='text/troff',['ttl'
]='text/turtle',['uri']='text/uri-list',['uris']='text/uri-list',['urls']=
'text/uri-list',['vcard']='text/vcard',['a']=' .a',['abc']=' .abc',['curl']=
'text/vnd.curl',['dcurl']='text/vnd.curl.dcurl',['mcurl']='text/vnd.curl.mcurl',
['scurl']='text/vnd.curl.scurl',['debian.copyright']=' .debian.copyright',[
'dmclientscript']=' .dmclientscript',['sub']='text/vnd.dvb.subtitle',[
'esmertec.theme-descriptor']=' .esmertec.theme-descriptor',['fly']=
'text/vnd.fly',['flx']='text/vnd.fmi.flexstor',['gv']='text/vnd.graphviz',[
'3dml']='text/vnd.in3d.3dml',['spot']='text/vnd.in3d.spot',['iptc.newsml']=
' .iptc.newsml',['iptc.nitf']=' .iptc.nitf',['latex-z']=' .latex-z',[
'motorola.reflex']=' .motorola.reflex',['ms-mediapackage']=' .ms-mediapackage',[
'net2phone.commcenter.command']=' .net2phone.commcenter.command',[
'radisys.msml-basic-layout']=' .radisys.msml-basic-layout',['si.uricatalogue']=
' .si.uricatalogue',['jad']='text/vnd.sun.j2me.app-descriptor',[
'trolltech.linguist']=' .trolltech.linguist',['wap.si']=' .wap.si',['wap.sl']=
' .wap.sl',['wml']='text/vnd.wap.wml',['wmls']='text/vnd.wap.wmlscript',['s']=
'text/x-asm',['asm']='text/x-asm',['c']='text/x-c',['cc']='text/x-c',['cxx']=
'text/x-c',['cpp']='text/x-c',['h']='text/x-c',['hh']='text/x-c',['dic']=
'text/x-c',['f']='text/x-fortran',['for']='text/x-fortran',['f77']=
'text/x-fortran',['f90']='text/x-fortran',['java']='text/x-java-source',['nfo']=
'text/x-nfo',['opml']='text/x-opml',['p']='text/x-pascal',['pas']=
'text/x-pascal',['etx']='text/x-setext',['sfv']='text/x-sfv',['uu']=
'text/x-uuencode',['vcs']='text/x-vcalendar',['vcf']='text/x-vcard',['3gp']=
'video/3gpp',['3g2']='video/3gpp2',['h261']='video/h261',['h263']='video/h263',[
'h264']='video/h264',['segment']=' .segment',['jpgv']='video/jpeg',['jpm']=
'video/jpm',['jpgm']='video/jpm',['mj2']='video/mj2',['mjp2']='video/mj2',['mp4'
]='video/mp4',['mp4v']='video/mp4',['mpg4']='video/mp4',['mpeg']='video/mpeg',[
'mpg']='video/mpeg',['mpe']='video/mpeg',['m1v']='video/mpeg',['m2v']=
'video/mpeg',['ogv']='video/ogg',['qt']='video/quicktime',['mov']=
'video/quicktime',['cctv']=' .cctv',['uvh']='video/vnd.dece.hd',['uvvh']=
'video/vnd.dece.hd',['uvm']='video/vnd.dece.mobile',['uvvm']=
'video/vnd.dece.mobile',['dece.mp4']=' .dece.mp4',['uvp']='video/vnd.dece.pd',[
'uvvp']='video/vnd.dece.pd',['uvs']='video/vnd.dece.sd',['uvvs']=
'video/vnd.dece.sd',['uvv']='video/vnd.dece.video',['uvvv']=
'video/vnd.dece.video',['directv.mpeg']=' .directv.mpeg',['directv.mpeg-tts']=
' .directv.mpeg-tts',['dlna.mpeg-tts']=' .dlna.mpeg-tts',['dvb']=
'video/vnd.dvb.file',['fvt']='video/vnd.fvt',['hns.video']=' .hns.video',[
'iptvforum.1dparityfec-1010']=' .iptvforum.1dparityfec-1010',[
'iptvforum.1dparityfec-2005']=' .iptvforum.1dparityfec-2005',[
'iptvforum.2dparityfec-1010']=' .iptvforum.2dparityfec-1010',[
'iptvforum.2dparityfec-2005']=' .iptvforum.2dparityfec-2005',['iptvforum.ttsavc'
]=' .iptvforum.ttsavc',['iptvforum.ttsmpeg2']=' .iptvforum.ttsmpeg2',[
'motorola.video']=' .motorola.video',['motorola.videop']=' .motorola.videop',[
'mxu']='video/vnd.mpegurl',['m4u']='video/vnd.mpegurl',['pyv']=
'video/vnd.ms-playready.media.pyv',['nokia.interleaved-multimedia']=
' .nokia.interleaved-multimedia',['nokia.videovoip']=' .nokia.videovoip',[
'objectvideo']=' .objectvideo',['radgamettools.bink']=' .radgamettools.bink',[
'radgamettools.smacker']=' .radgamettools.smacker',['sealed.mpeg1']=
' .sealed.mpeg1',['sealed.mpeg4']=' .sealed.mpeg4',['sealed.swf']=' .sealed.swf'
,['sealedmedia.softseal.mov']=' .sealedmedia.softseal.mov',['uvu']=
'video/vnd.uvvu.mp4',['uvvu']='video/vnd.uvvu.mp4',['viv']='video/vnd.vivo',[
'webm']='video/webm',['f4v']='video/x-f4v',['fli']='video/x-fli',['flv']=
'video/x-flv',['m4v']='video/x-m4v',['mkv']='video/x-matroska',['mk3d']=
'video/x-matroska',['mks']='video/x-matroska',['mng']='video/x-mng',['asf']=
'video/x-ms-asf',['asx']='video/x-ms-asf',['vob']='video/x-ms-vob',['wm']=
'video/x-ms-wm',['wmv']='video/x-ms-wmv',['wmx']='video/x-ms-wmx',['wvx']=
'video/x-ms-wvx',['avi']='video/x-msvideo',['movie']='video/x-sgi-movie',['smv']
='video/x-smv',['ice']='x-conference/x-cooltalk'}end function
__DARKLUA_BUNDLE_MODULES.q()local b=
[[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/]]function enc
(data)return((data:gsub('.',function(x)local r,b='',x:byte()for i=8,1,-1 do r=r
..(b%2^i-b%2^(i-1)>0 and'1'or'0')end return r end)..'0000'):gsub(
'%d%d%d?%d?%d?%d?',function(x)if(#x<6)then return''end local c=0 for i=1,6 do c=
c+(x:sub(i,i)=='1'and 2^(6-i)or 0)end return b:sub(c+1,c+1)end)..({'','==','='})
[#data%3+1])end function dec(data)data=string.gsub(data,'[^'..b..'=]','')return(
data:gsub('.',function(x)if(x=='=')then return''end local r,f='',(b:find(x)-1)
for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and'1'or'0')end return r end):gsub(
'%d%d%d?%d?%d?%d?%d?%d?',function(x)if(#x~=8)then return''end local c=0 for i=1,
8 do c=c+(x:sub(i,i)=='1'and 2^(7-i)or 0)end return string.char(c)end))end
function safe_enc(data,log)if log==nil then log=true end local CHUNK_SIZE=math.
floor(68266.66666666667)*3 local encoded=''local chunks={}while#data>0 do table.
insert(chunks,data:sub(1,CHUNK_SIZE))data=data:sub(CHUNK_SIZE+1)end for i,chunk
in ipairs(chunks)do if log then print(('[http] Encoding B64 chunk %s/%s'):
format(i,#chunks))end encoded=encoded..enc(chunk)wait()end return encoded end
return{encode=safe_enc,decode=dec}end function __DARKLUA_BUNDLE_MODULES.r()local
httpservice=game:GetService('HttpService')local MIME=__DARKLUA_BUNDLE_MODULES.
load('p')local b64=__DARKLUA_BUNDLE_MODULES.load('q')local function randomString
(l)local s=''for _=1,l do s=s..string.char(math.random(97,122))end return s end
local File={}File.__index=File function File.new(...)local self=setmetatable({},
File)self.__IsFile=true self.name='unknown'self.content=''self.content_type=nil
local args={...}if#args==1 then self.content=args[1]elseif#args>=2 then self.
name=args[1]self.content=args[2]self.content_type=args[3]end if not self.
content_type then local ext=self.name:split('.')ext=ext[#ext]self.content_type=
MIME[ext:lower()]or'text/plain'end if type(self.content)~='string'then error((
'[http] Invalid file content for file %s'):format(self.name))end return self end
function File:__tostring()return("File('%s', '%s')"):format(self.name,self.
content_type)end local FormData={}FormData.__index=FormData function FormData.
new(fields)local self=setmetatable({},FormData)self.__FormData=true fields=
fields or{}self.boundary='--FormBoundary-'..randomString(28)self.content_type=
'application/x-www-form-urlencoded'self.fields={}for k,v in pairs(fields)do self
:AddField(k,v)end return self end function FormData:AddField(name,value)if value
.__IsFile then self.content_type='multipart/form-data; boundary="'..self.
boundary..'"'end table.insert(self.fields,{Name=name,Value=value})end function
FormData:build()local content=''if self.content_type==
'application/x-www-form-urlencoded'then for _,field in ipairs(self.fields)do if
field.Value.__IsFile then error(
'[http] URL encoded forms cannot contain any files')end if field.Name:find('=')
or field.Name:find('&')then error(
"[http] Form field names must not contain '=' or '&'")end if type(field.Value)==
'table'then for _,val in ipairs(field.Value)do if#content>0 then content=content
..'&'end content=content..field.Name..'='..httpservice:UrlEncode(val)end else if
#content>0 then content=content..'&'end content=content..field.Name..'='..
httpservice:UrlEncode(field.Value)end end else for _,field in pairs(self.fields)
do content=content..'--'..self.boundary..'\r\n'local val=field.Value content=
content..('Content-Disposition: form-data; name="%s"'):format(field.Name)if
field.Value.__IsFile then val=field.Value.content content=content..(
'; filename="%s"'):format(field.Value.name)content=content..'\r\nContent-Type: '
..field.Value.content_type if field.Value.content_type:sub(1,5)~='text/'then val
=b64 .encode(val)content=content..'\r\nContent-Transfer-Encoding: base64'end end
content=content..'\r\n\r\n'..val..'\r\n'end content=content..'--'..self.boundary
..'--'end return content end return{['FormData']=FormData,['File']=File}end
function __DARKLUA_BUNDLE_MODULES.s()local Promise=__DARKLUA_BUNDLE_MODULES.
load('f')local function createFetch(promise_request)local function fetch(url,
options)if options==nil then options={}end local method=options.method or'GET'
options.method=nil options.data=options.body options.body=nil return
promise_request(method,url,options):andThen(function(response)local text=
response.text response.text=function()return Promise.resolve(text)end response.
status=response.code return response end)end return fetch end return createFetch
end end local html=__DARKLUA_BUNDLE_MODULES.load('c')local Request=
__DARKLUA_BUNDLE_MODULES.load('n')local Session=__DARKLUA_BUNDLE_MODULES.load(
'o')local Forms=__DARKLUA_BUNDLE_MODULES.load('r')local RateLimiter=
__DARKLUA_BUNDLE_MODULES.load('k')local Util=__DARKLUA_BUNDLE_MODULES.load('l')
local createFetch=__DARKLUA_BUNDLE_MODULES.load('s')local http={}http.VERSION=
'0.5.4'http.Request=Request.new http.Session=Session.new http.FormData=Forms.
FormData.new http.File=Forms.File.new http.cache=__DARKLUA_BUNDLE_MODULES.load(
'm')function http.request(method,url,opts)opts=opts or{}local req=Request.new(
method,url,opts)return req:send()end http.send=Util.deprecate(http.request,'0.5'
,'http.send')function http.promise_request(method,url,opts)opts=opts or{}local
req=Request.new(method,url,opts)return req:send(true)end http.promise_send=Util.
deprecate(http.promise_request,'0.5','http.promise_send')http.fetch=createFetch(
http.promise_request)for _,method in pairs({'GET','POST','HEAD','OPTIONS','PUT',
'DELETE','PATCH'})do http[method:lower()]=function(url,opts)return http.request(
method,url,opts)end http['promise_'..method:lower()]=function(url,opts)return
http.promise_request(method,url,opts)end end function http.set_ratelimit(
requests,period)local rl=RateLimiter.get('http',requests,period)print(
'[http] RateLimiter settings changed: ',rl.rate,'reqs /',rl.window_size,'secs')
end function http.parse_html(html_string,page_url)return html.parse(html_string,
100000,page_url)end http.parse_xml=http.parse_html return http