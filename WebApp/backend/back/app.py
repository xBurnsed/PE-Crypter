import os
import subprocess
from shutil import copyfile
from flask import Flask, request, jsonify, send_from_directory, after_this_request
from flask_cors import CORS


ALLOWED_EXTENSIONS = {'exe','ico'}

app = Flask(__name__, static_folder='finalStubFile')
CORS(app)

fileToCrypt = None
outputFileName = ""
sigFile = None


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# No cacheing at all for API endpoints.
@app.after_request
def add_header(response):
    # response.cache_control.no_store = True
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store'
    return response
    
@app.route('/downloadcryptedfile', methods=['GET'])
def DownloadCryptedFile():
    response = send_from_directory(directory=app.static_folder, filename=outputFileName, mimetype="application/vnd.microsoft.portable-executable", as_attachment=True, cache_timeout=0)
    return response

@app.route('/cryptfile',  methods=['POST'])
def CryptFile():
    
    #Receiving data
    global fileToCrypt
    fileToCrypt = request.files['fileToCrypt']

    encKey = request.form['encKey']
    iconFile = request.files['iconFile']

    global sigFile
    sigFile = request.files['sigFile']

    global outputFileName
    outputFileName = request.form['outputFileName']

    fileToCrypt.save(os.path.join('uploadedFiles',fileToCrypt.filename))
    sigFile.save(os.path.join('uploadedFiles', sigFile.filename))

    iconFile.save(os.path.join("C:\\Users\\uli_6\\Desktop\\TFGCode\\PELoader\\PELoader\\Icons\\Icon.ico"))

    peEncrypterCommand = "PEEncrypter.exe uploadedFiles/"+fileToCrypt.filename+ " "+ encKey
    subprocess.call(peEncrypterCommand)

    copyfile("shellc.h","C:\\Users\\uli_6\\Desktop\\TFGCode\\PELoader\\PELoader\\shellc.h")
       
    compileStubCommand = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe C:\\Users\\uli_6\\Desktop\\TFGCode\\PELoader /property:Configuration=Release /p:PlatformTarget=x86 /p:Platform=x86"
    subprocess.call(compileStubCommand)

    copyfile("C:\\Users\\uli_6\\Desktop\\TFGCode\\PELoader\\Release\\PELoader.exe","C:\\Users\\uli_6\\Desktop\\CrypterWebApp\\backend\\back\\finalStubFile\\PELoader.exe")
    
    signatureCloneCommand = "SignatureClone.exe uploadedFiles/"+sigFile.filename+" finalStubFile/PELoader.exe finalStubFile/"+outputFileName
    subprocess.call(signatureCloneCommand)
    
    #Clone manifest from the same file we are clonning a signature. We could also add a new Exe..
    #manifestCloneCommand1 = "mt.exe -inputresource:uploadedFiles/"+sigFile.filename+";1 -out:"+sigFile.filename+".manifest"
    #manifestCloneCommand2 = "mt.exe -nologo -manifest "+ sigFile.filename+".manifest -outputresource:finalStubFile/"+outputFileName+";1" 

    #subprocess.call(manifestCloneCommand1)
    #subprocess.call(manifestCloneCommand2)

    response = jsonify({
        'message': '¡Se ha enviado la solicitud con éxito!',
        'outputFileName': outputFileName,
        'status': 200
    })
    response.status_code = 200

    return response



if __name__ == "__main__":
    app.run(debug=True)