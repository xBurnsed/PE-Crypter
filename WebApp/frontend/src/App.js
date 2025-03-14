import {Fragment} from 'react';
import Header from './components/Header/Header.js';
import Main from './components/Main/Main.js';
import ParticlesBg from 'particles-bg';
import './App.scss';

const App = () => {
  return (
    <Fragment>
        <div className={"backgroundHolder"} />
        <ParticlesBg color="F08080" type="cobweb" bg={true} /> 
        <div className={"container-fluid vertical-center"}>
          <Header/>
          <Main/>
        </div>
    </Fragment>
  );
}

export default App;
