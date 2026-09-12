import express from 'express';
import serverless from 'serverless-http';

// ThreatLens was originally built as a traditional Express server for
// Google AI Studio / Cloud Run. Netlify runs Express through Functions,
// so prevent the imported server module from opening a long-lived port.
(express.application as any).listen = function () {
  return this;
};

process.env.NETLIFY = 'true';
process.env.NODE_ENV = 'production';

let cachedHandler: ReturnType<typeof serverless> | null = null;
let initialization: Promise<ReturnType<typeof serverless>> | null = null;

async function getHandler() {
  if (cachedHandler) return cachedHandler;

  if (!initialization) {
    initialization = import('../../server.js').then(({ app }) => {
      cachedHandler = serverless(app);
      return cachedHandler;
    });
  }

  return initialization;
}

export const handler = async (event: any, context: any) => {
  const appHandler = await getHandler();
  return appHandler(event, context);
};
