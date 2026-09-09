const app = require('./app');

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Calculadora de Obra rodando em http://localhost:${PORT}`);
});