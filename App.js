import React from 'react';
import './App.css';
import DropdownMenu from './DropdownMenu';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <div className="header">
          <p className="p11">Well-being</p>
          <h1 className="p12">Платформа для вашего благополучия</h1>
          <h2 className="menu">
            Menu
            <div>
              <button className="butt">Пункт 1</button>
              <br></br>
              <button className="butt">Пункт 2</button>
              <br></br>
              <button className="butt">Пункт 3</button>
              <br></br>
              <button className="butt">Пункт 4</button>
            </div>
          </h2>
        </div>
      </header>
    </div>
  );
}

export default App;
