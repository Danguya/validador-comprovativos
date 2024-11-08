const express = require('express');
const multer = require('multer');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const port = 3000;

// Configuração do EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware para servir arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Configuração do CORS
app.use(cors());
app.use(express.json());

// Configuração do multer para uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, file.originalname),
});
const upload = multer({ storage });

// Rota para renderizar a página principal
app.get('/', (req, res) => {
  res.render('index'); // Renderiza a view `index.ejs`
});

// Endpoint para verificação de comprovativos
app.post('/scan', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  }

  const filePath = req.file.path;
  const yaraRulePath = path.join(__dirname, 'yara-rules', 'regras.yar');

  exec(`yara ${yaraRulePath} ${filePath}`, (error, stdout, stderr) => {
    if (error) return res.status(500).json({ error: `Erro ao executar YARA: ${error.message}` });
    if (stderr) return res.status(500).json({ error: `stderr: ${stderr}` });

    if (stdout.includes('MCX_ATLANTICO')) {
      return res.json({ message: 'Comprovado' });
    } else if (stdout.includes('MCX_BCI')) {
      return res.json({ message: 'Comprovado' });
    } else if (stdout.includes('MCX_KEVE')) {
      return res.json({ message: 'Comprovado' });
    } else if (stdout.includes('MCX_BAI')) {
      return res.json({ message: 'Comprovado' });
    } else if (stdout.includes('MCX_BFA')) {
      return res.json({ message: 'Comprovado' });
    } else if (stdout.includes('MCX_STANDARD_BANK')) {
      return res.json({ message: 'Comprovado' });
    } else {
      return res.json({ message: 'Comprovativo inválido ou falsificado' });
    }
  });
});

app.listen(port, () => console.log(`Servidor rodando em http://localhost:${port}`));
