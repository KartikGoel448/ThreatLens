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

const { app } = await import('../../server.js');

export const handler = serverless(app);
