# import json
# from base_reader import BaseReader

# class JsonReader(BaseReader):
#     def __init__(self, path):
#         self.path = path

#     def read_events(self):
#         try:
#             with open(self.path, "r", encoding="utf-8") as f:
#                 for line in f:
#                     try:
#                         data = json.loads(line)
#                         yield data
#                     except:
#                         continue
#         except Exception as e:
#             print(f"[JsonReader ERROR] {e}")

import json
from base_reader import BaseReader

class JsonReader(BaseReader):
    def __init__(self, path):
        self.path = path

    def read_events(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        yield data
                    except:
                        continue
        except Exception as e:
            print(f"[JsonReader ERROR] {e}")
