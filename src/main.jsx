import React from 'react';
import { createRoot } from 'react-dom/client';
import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import App from './App';
import './styles.css';

const theme = createTheme({
  palette: {
    primary: { main: '#1565c0' },
  },
});

const rootElement = document.getElementById('root');

createRoot(rootElement).render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <App />
      <ToastContainer position="bottom-right" />
    </ThemeProvider>
  </React.StrictMode>,
);
