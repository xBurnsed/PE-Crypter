import React, { Fragment } from 'react';

import './AlertDialog.scss';
import fileDownload from './fileDownload.png';

const AlertDialog = (props) => {
    return (
        <Fragment>
            <div className="modalDial"  tabIndex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true" autoFocus={true}>
                <div className="modal-dialog" role="document">
                    <div className="modal-content">
                    <div className="modal-header">
                        <h5 className="modal-title">{props.titulo}</h5>
                        <button type="button" className="close" data-dismiss="modal" aria-label="Close" onClick={props.resetDialog}>
                        <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div className="modal-body">
                        <p>{props.cuerpo}</p>
                    </div>
                    <div className="modal-footer">
                        <button onClick={props.handleDialog} type="button" className="btn-lg btn-block btn-light"  data-dismiss="modal"><img src={fileDownload} alt="Download file..." height="20%" width="20%" className={"pr-2"} />DOWNLOAD FILE!</button>
                    </div>
                    </div>
                </div>
            </div>
            <div className="blackBackgroundAlert"/>
        </Fragment>
    );
}

export default AlertDialog;