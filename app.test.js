const request = require('supertest');
const app = require('./app');

describe('POST /scan', () => {
  it('should return "Comprovativo fidedigno" if the file is valid', async () => {
    const res = await request(app)
      .post('/scan')
      .attach('file', 'path/to/valid/file.pdf');
    
    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Comprovativo fidedigno');
  });

  it('should return "Comprovativo falso" if the file is invalid', async () => {
    const res = await request(app)
      .post('/scan')
      .attach('file', 'path/to/invalid/file.pdf');
    
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Comprovativo falso: Magic number ou tamanho inválido');
  });
});

