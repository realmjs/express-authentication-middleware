"use strict"

const jwt = require('jsonwebtoken');

const setupEnvironmentVariables = () => process.env.REALM_SECRET_KEY = "realm-secret-key";
const clearEnvironmentVariables = () => process.env.REALM_SECRET_KEY = undefined;

const createResMock = () => {
  return {
    status(code) { this.statusCode = code; return { json: this.json }; },
    json: jest.fn(),
    statusCode: undefined,
    locals: {},
  };
};

beforeEach( () => jest.clearAllMocks() );
beforeAll( () => setupEnvironmentVariables() );
afterAll( () => clearEnvironmentVariables() );

const authenticateRequest = require('../src/authenticateRequest');

test("authenticate request decode and return valid uid in res.locals", () => {

  const uid = 'test-uid';
  const secret = process.env.REALM_SECRET_KEY;
  const credential = jwt.sign({ uid }, secret);

  const req = {
    headers: {
      authorization: `Bearer ${credential}`
    }
  };

  const next = jest.fn();

  const res = createResMock();

  authenticateRequest(secret)()(req, res, next);

  expect(res.statusCode).toBeUndefined();
  expect(res.json).toHaveBeenCalledTimes(0);
  expect(res.locals).toEqual({ token: credential, uid });
  expect(next).toHaveBeenCalledTimes(1);
  expect(next.mock.calls[0].length).toEqual(0);

});

test("authenticate request response 401 if missing authentication bearer", () => {

  const secret = process.env.REALM_SECRET_KEY;

  const req = {
    headers: {}
  };

  const res = createResMock();

  const next = jest.fn();

  authenticateRequest(secret)()(req, res, next);

  expect(res.statusCode).toBe(401);
  expect(res.json).toHaveBeenCalledTimes(1);
  expect(res.locals).toEqual({});
  expect(next).toHaveBeenCalledTimes(0);

});

test("authenticate request response 401 for invalid credential", () => {

  const secret = 'fake-secret-key';
  const credential = jwt.sign(true, secret);

  const req = {
    headers: {
      authorization: `Bearer ${credential}`
    }
  };

  const res = createResMock();

  const next = jest.fn();

  authenticateRequest(process.env.REALM_SECRET_KEY)()(req, res, next);

  expect(res.statusCode).toBe(401);
  expect(res.json).toHaveBeenCalledTimes(1);
  expect(res.locals.uid).toBeUndefined();
  expect(next).toHaveBeenCalledTimes(0);

});
