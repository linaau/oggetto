import React, { useState } from 'react';
import './App.css';

function App() {
  const [menuOpen, setMenuOpen] = useState(false);

  const toggleMenu = () => {
    setMenuOpen(!menuOpen);
  };

  return (
    <div className="App">
      <button onClick={toggleMenu}>Открыть меню</button>

      {menuOpen && (
        <div className="menu">
          <ul>
            <li>Вход</li>
            <li>Мероприятия</li>
            <li>Пункт меню 3</li>
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;
