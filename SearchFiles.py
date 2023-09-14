"""
SYNOPSIS

    SearchFiles

DESCRIPTION

    Searches reversed Android codebases for vulnerabilities from the OWASP Mobile Testing Plan, and
    POINT research

USAGE

    python SearchFiles

AUTHOR

    Bill Sempf <bill@pointweb.net>

VERSION

    0.1.0.0
"""

import os

def main(logFile="C:\Temp/result.txt", projectPath="c\:temp\project"):
    with open(logFile, "w") as results:
        for root, dirs, files in os.walk(projectPath, topdown=False):
            for filename in files:
                with open(os.path.join(root,filename)) as currentFile:
                    text = currentFile.read()
                    if ('MODE_PRIVATE' in text) or \
                            ('MODE_WORLD_READABLE' in text) or \
                            ('MODE_WORLD_WRITEABLE' in text) or \
                            ('addPreferencesFromResource' in text):
                        results.write('Potentially leaking sensitive information in ' + os.path.join(root, filename) + '\n')
                    if ('WRITE_EXTERNAL_STORAGE' in text) or \
                            ('getExternalStorageDirectory()' in text):
                        results.write('Application may be leaking information to SD Card in ' +
                                    os.path.join(root, filename) + '\n')
                    if ('<Button>' in text) and not ('filterTouchesWhenObscured="true"' in text):
                        results.write('Potential tapjacking in ' +
                                    os.path.join(root, filename) + '\n')
                    if ('addJavascriptInterface()' in text) or \
                            ('setJavaScriptEnabled(true)' in text):
                        results.write('Insecure webview in ' +
                                    os.path.join(root, filename) + '\n')
                    if ('////' in text) or \
                            ('//* *//' in text):
                        results.write('Comments found in ' +
                                    os.path.join(root, filename) + '\n')
                    if ('<Input>' in text) and not \
                            ('textNoSuggestions' in text):
                        results.write('Potential enumeration of sensitive information in ' +
                                    os.path.join(root, filename) + '\n')
                    if ('db)' in text) or \
                            ('sqlite' in text) or \
                            ('database' in text) or \
                            ('insert' in text) or \
                            ('select' in text) or \
                            ('delete' in text) or \
                            ('table' in text) or \
                            ('cursor' in text) or \
                            ('rawquery' in text):
                        results.write('Potential for injection in ' +
                                    os.path.join(root, filename) + '\n')
                    if 'Log.' in text:
                        results.write('Potentially leaking sensitive logging information in ' +
                                    os.path.join(root, filename) + '\n')
                    if ('MD5' in text) or \
                            ('Base64' in text) or \
                            ('DES' in text):
                        results.write('Potential use of insecure encryption in ' +
                                    os.path.join(root, filename) + '\n')
                    if 'Toast.makeText' in text:
                        results.write('Potentially leaking sensitive toast information in ' +
                                    os.path.join(root, filename) + '\n')
                    if ('uid)' in text) or \
                            ('user-id' in text) or \
                            ('imei' in text) or \
                            ('deviceId' in text) or \
                            ('deviceSerialNumber' in text) or \
                            ('devicePrint' in text) or \
                            ('X-DSN' in text) or \
                            ('phone' in text) or \
                            ('mdn' in text) or \
                            ('did' in text) or \
                            ('IMSI' in text) or \
                            ('uuid' in text):
                        results.write('Potential leakage of device information in ' +
                                    os.path.join(root, filename) + '\n')
                    if 'Action.GetIntent()' in text:
                        results.write('Potential intent injection in ' +
                                    os.path.join(root, filename) + '\n')
                    if ('getLastKnownLocation()' in text) or \
                            ('requestLocationUpdates()' in text) or \
                            ('getLatitude()' in text) or \
                            ('getLongitude()' in text) or \
                            ('LOCATION' in text):
                        results.write('Potential leakage of location information in ' +
                                    os.path.join(root, filename) + '\n')
                    if ('SYSTEM_ALERT_WINDOW' in text) or \
                            ('BIND_ACCESSIBILITY_SERVICE' in text):
                        results.write('Potential Cloak and Dagger vulnerability in ' +
                                    os.path.join(root, filename) + '\n')
main()