import React, {Fragment, useState} from 'react';
import axios from 'axios';
import AlertDialog from './AlertDialog/AlertDialog.js';
import './Main.scss';

function makeid(length) {
    var result           = '';
    var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for ( var i = 0; i < length; i++ ) {
       result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

const Main = (props) => {
    const [showSpinner, setShowSpinner] = useState(false);
    const [showDialog, setShowDialog] = useState({
        mostrar:false,
        titulo:"",
        cuerpo:""
    });
    const [outputFileName, setOutputFileName] = useState("");

    const resetDialog = () =>{
        setShowDialog({
            mostrar:false,
            titulo:"",
            cuerpo:""
        });

        setOutputFileName("");
        setFileToCrypt("");
        setIconFile("");
        setSigFile("");
        setFormText(defaultFormText);
    }

    const downloadDialog = () => {

        console.log("He entrado")
        axios({
            url: 'http://localhost:5000/downloadcryptedfile', //your url
            method: 'GET',
            responseType: 'blob', // important
            }).then((response) => {
                console.log(response)
                const url = window.URL.createObjectURL(new Blob([response.data]));
                const link = document.createElement('a');
                link.href = url;
                link.setAttribute('download', outputFileName); //or any other extension
                document.body.appendChild(link);
                link.click();
            }).catch(error => console.log(error));
        
        resetDialog();
    }

    const [fileToCrypt, setFileToCrypt] = useState("");
    const [iconFile, setIconFile] = useState("");
    const [sigFile, setSigFile] = useState("");

    const defaultFormText = {
        encKey:"",
        outputFileName:""
    };    
    const [formText, setFormText] = useState(defaultFormText)

    const handleChangeText = (e) => {
        setFormText({
            ...formText,
            [e.target.name]: e.target.value
        });
    }

    const onSubmitForm =  (e) =>{
        e.preventDefault();
        setShowSpinner(true);

        const formData = new FormData();
        formData.append("fileToCrypt", fileToCrypt)
        formData.append("encKey", formText.encKey)
        formData.append("iconFile", iconFile)
        formData.append("sigFile", sigFile)
        formData.append("outputFileName",formText.outputFileName)
       
        const url = 'http://localhost:5000/cryptfile';
        axios.post(url,formData)
            .then(res => {
                console.log(res);
                if(res.status === 200){
                    console.log(res.data);
                    setShowDialog({
                        mostrar:true,
                        titulo:"YOUR FILE IS READY!",
                        cuerpo:"Press the button below to download your new crypted file!"
                    });
                    setOutputFileName(res.data.outputFileName);
                }
            })
            .finally(function(){
                setShowSpinner(false);
            })
            .catch(error => console.log(error));
    }
     
    const onClickGenerate = () => {
        setFormText({
            ...formText,
            encKey: makeid(32)
        });
    }

    return (
        <Fragment>
            <div className={"container col-4 p-5 text-dark rounded-bottom backgroundGradient"}>
            {showDialog.mostrar ? <AlertDialog titulo={showDialog.titulo} cuerpo={showDialog.cuerpo} handleDialog={downloadDialog} resetDialog={resetDialog}/>: null}
                <form className="pl-4 pr-4" encType="multipart/form-data" onSubmit={onSubmitForm}>
                    <h2>File to crypt: </h2>
                    <div className="input-group">
                        <div className="custom-file">
                            <input type="file" className="custom-file-input" name="fileToCrypt" accept=".exe" id="inputGroupFile01"  onChange={(e) => setFileToCrypt(e.target.files[0])} />
                            <label className="custom-file-label" htmlFor="inputGroupFile01">{fileToCrypt === "" ? "Choose a file..." : fileToCrypt.name}</label>
                        </div>
                    </div>
                    
                    <h2 className={"mt-3"}>Encryption key: </h2>                                 
                    <div className={"input-group mr-4"}>
                        <input type="text" name="encKey" className={"form-control"} placeholder="Encryption Key" value={formText.encKey} onChange={handleChangeText}/>
                        <div className={"input-group-append"}>  
                            <button type="button" className="btn btn-dark" onClick={onClickGenerate}>Generate</button>
                        </div>
                    </div>

                    <h2 className={"mt-3"}>Select an icon: </h2>

                    <div className="input-group">
                        <div className="custom-file">
                            <input type="file" className="custom-file-input" name="iconFile" accept=".ico" id="inputGroupFile02"  onChange={(e) => setIconFile(e.target.files[0])} />
                            <label className="custom-file-label" htmlFor="inputGroupFile02">{iconFile === "" ? "Choose a file..." : iconFile.name}</label>
                        </div>
                    </div>

                    <h2 className={"mt-3"}>Signature to spoof: </h2>

                    <div className="input-group">
                        <div className="custom-file">
                            <input type="file" className="custom-file-input" name="sigFile" accept=".exe" id="inputGroupFile03"  onChange={(e) => setSigFile(e.target.files[0])} />
                            <label className="custom-file-label" htmlFor="inputGroupFile03">{sigFile === "" ? "Choose a file..." : sigFile.name}</label>
                        </div>
                    </div>

                    <h2 className={"mt-3"}>Output filename: </h2>
                    <input type="text" name="outputFileName" className={"form-control"} placeholder="Default: output.exe" value={formText.outputFileName} onChange={handleChangeText}/>
                    
                    
                    {showSpinner ? 
                        <button className="mt-3 btn-lg btn-block btn-success px-2" type="button" disabled>
                            <span className="spinner-border mr-2" style={{"width": "1.3rem","height": "1.3rem"}} role="status" aria-hidden="true"></span>
                                Crypting file... This might take a few seconds.
                        </button> : 
                        <button type="submit" className="mt-3 btn-lg btn-block btn-dark">CRYPT FILE!</button>}

                </form>
            </div>
        </Fragment>
    );
}

export default Main;