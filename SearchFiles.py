__author__ = 'Bill'

import os
with open("C:/Temp/result.txt", "w") as f:
    for root, dirs, files in os.walk("C:/Temp/project", topdown=False):
        for filename in files:
            with open(os.path.join(root,filename)) as currentFile:
                text = currentFile.read()
                if ('MODE_PRIVATE' in text) or ('MODE_WORLD_READABLE' in text) or ('MODE_WORLD_WRITEABLE' in text) or ('addPreferencesFromResource' in text):
                   f.write('potentially leaking sensitive information in ' + os.path.join(root,filename) + '\n')
