/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_BACKEND_URL: string;
    readonly VITE_SOCKET_URL: string;
    // add more env variables here if needed
  }
  
  interface ImportMeta {
    readonly env: ImportMetaEnv;
  }
  