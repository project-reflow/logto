import Koa from 'koa';
import request from 'supertest';
import { z } from 'zod';

import koaGuard from './koa-guard.js';

/**
 * Uses the real `koa-body` (the main guard tests mock it) to check that a guarded route rejects
 * an oversized JSON body before zod parses it.
 */
const createApp = () => {
  const app = new Koa();
  app.use(
    koaGuard({
      body: z.object({ values: z.record(z.string().regex(/^[\dA-Za-z]+$/), z.unknown()) }),
      status: [204, 400],
    })
  );
  app.use((ctx) => {
    ctx.status = 204;
  });
  return app.callback();
};

/** A JSON body of roughly `bytes` or more, whose keys all fail the key regex. */
const jsonOfSize = (bytes: number) => {
  const pairs = Array.from(
    { length: Math.ceil(bytes / 8) },
    (_, index) => `"-${index.toString(36)}":0`
  );
  return `{"values":{${pairs.join(',')}}}`;
};

describe('koaGuard JSON body limit', () => {
  it('accepts a valid JSON body', async () => {
    const response = await request(createApp())
      .post('/')
      .set('Content-Type', 'application/json')
      .send('{"values":{"a1":1}}');
    expect(response.status).toBe(204);
  });

  it('answers 413 for a JSON body over the limit', async () => {
    const response = await request(createApp())
      .post('/')
      .set('Content-Type', 'application/json')
      .send(jsonOfSize(200 * 1024));
    expect(response.status).toBe(413);
  });

  it('still parses a failing JSON body under the limit', async () => {
    const response = await request(createApp())
      .post('/')
      .set('Content-Type', 'application/json')
      .send(jsonOfSize(50 * 1024));
    expect(response.status).toBe(400);
  });
});
