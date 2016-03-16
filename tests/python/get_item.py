#!/usr/bin/env python
import sys
if len(sys.argv) > 1:
   sys.path.insert(0, sys.argv[1])
import sysrepoPy as sr

def connect():
   try:
      sr.sr_connect('def', 1)
   except RuntimeError as e:
      print("Exception catched as expected") 
      return
   print("This should not be printed")

def getItem():
   c = sr.sr_connect('abc', 0)
   session = sr.sr_session_start(c, sr.SR_DS_STARTUP)
   val = sr.sr_get_item(session, "/test-module:main/str")
   print(val.xpath)
   print(val.type)
   print(val.data.string_val)
   
   val = sr.sr_get_item(session, "/test-module:main/i8")   
   print(val.xpath)
   print(val.data.int8_val)
 

   schema = sr.sr_get_schema(session, "example-module", None, None, sr.SR_SCHEMA_YANG)
   print(schema)
   sr.sr_session_stop(session)
   sr.sr_disconnect(c) 
   print('Ok')

def getItems():
   c = sr.sr_connect('abc', 0)
   session = sr.sr_session_start(c, sr.SR_DS_STARTUP)
   vals = sr.sr_get_items(session, "/test-module:main")
   for v in vals:
      print(v.xpath)
      print(v.type)
      print('======')   

   sr.sr_session_stop(session)
   sr.sr_disconnect(c) 
   print('Ok')

def listSchemas():
   c = sr.sr_connect('abc', 0)
   session = sr.sr_session_start(c, sr.SR_DS_STARTUP)
   schemas = sr.sr_list_schemas(session)
   for s in schemas:
      print(s.module_name, s.revision.revision)  

   sr.sr_session_stop(session)
   sr.sr_disconnect(c) 
   

if __name__ == "__main__":
   connect()
   getItem()
   getItems()
   listSchemas()
