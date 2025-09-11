import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

const app = express();

// Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '200kb' }));
app.use(morgan('tiny'));
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false
  })
);

// Utils
const onlyDigits = (s = '') => (s || '').toString().replace(/\D+/g, '');
const isRepeated = (digits) => /^(\d)\1{10,13}$/.test(digits);

// CPF
function validateCPF(raw) {
  const errors = [];
  const digits = onlyDigits(raw);
  if (digits.length !== 11) errors.push('CPF deve ter 11 dígitos');
  if (isRepeated(digits)) errors.push('CPF inválido (sequência repetida)');
  if (errors.length) return { valid: false, errors };

  const calcCheck = (baseLen) => {
    let sum = 0;
    for (let i = 0; i < baseLen; i++) sum += parseInt(digits[i]) * (baseLen + 1 - i);
    const mod = (sum * 10) % 11;
    return mod === 10 ? 0 : mod;
  };
  const d1 = calcCheck(9);
  const d2 = calcCheck(10);
  const valid = d1 === parseInt(digits[9]) && d2 === parseInt(digits[10]);
  return valid
    ? { valid: true, normalized: `${digits.slice(0,3)}.${digits.slice(3,6)}.${digits.slice(6,9)}-${digits.slice(9)}` }
    : { valid: false, errors: ['Dígitos verificadores inválidos'] };
}

// CNPJ
function validateCNPJ(raw) {
  const errors = [];
  const digits = onlyDigits(raw);
  if (digits.length !== 14) errors.push('CNPJ deve ter 14 dígitos');
  if (/^(\d)\1{13}$/.test(digits)) errors.push('CNPJ inválido (sequência repetida)');
  if (errors.length) return { valid: false, errors };

  const calcCheck = (len) => {
    const weights = len === 12 ? [5,4,3,2,9,8,7,6,5,4,3,2] : [6,5,4,3,2,9,8,7,6,5,4,3,2];
    let sum = 0;
    for (let i = 0; i < weights.length; i++) sum += parseInt(digits[i]) * weights[i];
    const mod = sum % 11;
    return mod < 2 ? 0 : 11 - mod;
  };
  const d1 = calcCheck(12);
  const d2 = calcCheck(13);
  const valid = d1 === parseInt(digits[12]) && d2 === parseInt(digits[13]);
  return valid
    ? { valid: true, normalized: `${digits.slice(0,2)}.${digits.slice(2,5)}.${digits.slice(5,8)}/${digits.slice(8,12)}-${digits.slice(12)}` }
    : { valid: false, errors: ['Dígitos verificadores inválidos'] };
}

// Email
function validateEmail(raw) {
  const errors = [];
  const s = (raw || '').toString().trim();
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;
  if (!s) errors.push('E-mail não informado');
  if (s.length > 320) errors.push('E-mail muito longo');
  if (!re.test(s)) errors.push('Formato de e-mail inválido');
  if (errors.length) return { valid: false, errors };
  return { valid: true, normalized: s.toLowerCase() };
}

// Password
function validatePassword(raw, policy = {}) {
  const errors = [];
  const s = (raw || '').toString();

  const minLength = Number(policy.minLength ?? 8);
  const maxLength = Number(policy.maxLength ?? 128);
  const requireUpper = policy.upper ?? true;
  const requireLower = policy.lower ?? true;
  const requireNumber = policy.number ?? true;
  const requireSymbol = policy.symbol ?? true;
  const forbidCommon = policy.forbidCommon ?? true;

  if (s.length < minLength) errors.push(`Senha deve ter no mínimo ${minLength} caracteres`);
  if (s.length > maxLength) errors.push(`Senha deve ter no máximo ${maxLength} caracteres`);
  if (requireUpper && !/[A-Z]/.test(s)) errors.push('Ao menos 1 letra maiúscula');
  if (requireLower && !/[a-z]/.test(s)) errors.push('Ao menos 1 letra minúscula');
  if (requireNumber && !/[0-9]/.test(s)) errors.push('Ao menos 1 número');
  if (requireSymbol && !/[!@#$%^&*(),.?":{}|<>_\-+=

\[\]

\\;/`'~]/.test(s)) errors.push('Ao menos 1 símbolo');

  if (forbidCommon) {
    const common = new Set([
      '123456','password','123456789','qwerty','abc123','111111','123123','senha','admin','iloveyou'
    ]);
    if (common.has(s.toLowerCase())) errors.push('Senha muito comum');
  }

  if (/^\s|\s$/.test(s)) errors.push('Não iniciar ou terminar com espaço');

  return errors.length ? { valid: false, errors } : { valid: true };
}

// Telefone BR
function validatePhoneBR(raw) {
  const s = onlyDigits(raw);
  const errors = [];
  const local = s.startsWith('55') ? s.slice(2) : s;
  if (local.length !== 10 && local.length !== 11) errors.push('Telefone deve ter 10 (fixo) ou 11 dígitos (celular)');
  const ddd = local.slice(0,2);
  if (!/^(1[1-9]|2[12478]|3[1-578]|4[1-9]|5[1345]|6[1-9]|7[1-9]|8[1-9]|9[1-9])$/.test(ddd)) errors.push('DDD inválido');
  if (local.length === 11 && local[2] !== '9') errors.push('Celular deve iniciar com 9');
  if (errors.length) return { valid: false, errors };

  const normalized = `+55 (${ddd}) ${local.slice(2,7)}-${local.slice(7)}`;
  return { valid: true, normalized };
}

// CEP
function validateCEP(raw) {
  const digits = onlyDigits(raw);
  if (digits.length !== 8) return { valid: false, errors: ['CEP deve ter 8 dígitos'] };
  const normalized = `${digits.slice(0,5)}-${digits.slice(5)}`;
  return { valid: true, normalized };
}

// RG
function validateRG(raw) {
  const digits = onlyDigits(raw);
  if (digits.length < 7 || digits.length > 9) return { valid: false, errors: ['RG deve ter entre 7 e 9 dígitos'] };
  return { valid: true, normalized: digits };
}

// Nome
function validateName(raw) {
  const s = (raw || '').trim();
  if (s.length < 2) return { valid: false, errors: ['Nome muito curto'] };
  if (!/^[A-Za-zÀ-ÿ\s'-]+$/.test(s)) return { valid: false, errors: ['Nome contém caracteres inválidos'] };
  return { valid: true, normalized: s.replace(/\s+/g, ' ') };
}

// Detecção inteligente
function detectType(value) {
  if (validatePhoneBR(value).valid) return 'phone-br';
  if (validateCPF(value).valid) return 'cpf';
  if (validateCNPJ(value).valid) return 'cnpj';
  if (validateCEP(value).valid) return 'cep';
  if (validateEmail(value).valid) return 'email';
  if (validatePassword(value).valid) return 'password';
  if (validateRG(value).valid) return 'rg';
  if (validateName(value).valid) return 'name';
  return null;
}

// Endpoints
app.get('/health', (req, res) => {
  res.json({ status: 'ok', now: new Date().toISOString() });
});

app.get('/detect', (req, res) => {
  const { value } = req.query;
  if (!value) return res.status(400).json({ error: 'Parâmetro "value" é obrigatório.' });
    const tipo = detectType(value);
  if (!tipo) return res.status(400).json({ error: 'Tipo de dado não reconhecido.' });

  res.json({
    type: tipo,
    input: String(value ?? ''),
    timestamp: new Date().toISOString(),
    sourceIP: req.ip
  });
});

// Endpoint inteligente com validação
app.get('/validate', (req, res) => {
  const { value } = req.query;
  if (!value) {
    return res.status(400).json({ error: 'Parâmetro "value" é obrigatório.' });
  }
  const tipo = detectType(value);
  if (!tipo) {
    return res.status(400).json({ error: 'Tipo de dado não reconhecido.' });
  }

  let result;
  switch (tipo) {
    case 'cpf': result = validateCPF(value); break;
    case 'cnpj': result = validateCNPJ(value); break;
    case 'email': result = validateEmail(value); break;
    case 'password': result = validatePassword(value, {}); break;
    case 'phone-br': result = validatePhoneBR(value); break;
    case 'cep': result = validateCEP(value); break;
    case 'rg': result = validateRG(value); break;
    case 'name': result = validateName(value); break;
    default: result = { valid: false, errors: ['Tipo não suportado'] };
  }

  res.json({
    type: tipo,
    input: tipo === 'password' ? '***' : String(value ?? ''),
    ...result,
    timestamp: new Date().toISOString(),
    sourceIP: req.ip
  });
});

// Batch
app.post('/validate/batch', (req, res) => {
  const items = Array.isArray(req.body) ? req.body : [];
  const out = items.map((item) => {
    const type = item?.type;
    const value = item?.value;
    switch (type) {
      case 'cpf': return { type, input: String(value ?? ''), ...validateCPF(value) };
      case 'cnpj': return { type, input: String(value ?? ''), ...validateCNPJ(value) };
      case 'email': return { type, input: String(value ?? ''), ...validateEmail(value) };
      case 'password': return { type, input: value ? '***' : '', policy: cleanPolicy(item.policy || {}), ...validatePassword(value, item.policy || {}) };
      case 'phone-br': return { type, input: String(value ?? ''), ...validatePhoneBR(value) };
      case 'cep': return { type, input: String(value ?? ''), ...validateCEP(value) };
      case 'rg': return { type, input: String(value ?? ''), ...validateRG(value) };
      case 'name': return { type, input: String(value ?? ''), ...validateName(value) };
      default: return { type, input: String(value ?? ''), valid: false, errors: ['Tipo não suportado'] };
    }
  });
  res.json(out);
});

// Teste de detecção
app.post('/test', (req, res) => {
  const values = Array.isArray(req.body) ? req.body : [];
  const out = values.map((value) => {
    const type = detectType(value);
    return {
      input: String(value ?? ''),
      detectedType: type ?? 'não reconhecido'
    };
  });
  res.json(out);
});

// Helpers
function parseBool(v, def) {
  if (v === undefined) return def;
  const s = String(v).toLowerCase();
  if (['true','1','yes','y'].includes(s)) return true;
  if (['false','0','no','n'].includes(s)) return false;
  return def;
}
function cleanPolicy(p) {
  return {
    minLength: Number(p.minLength ?? 8),
    maxLength: Number(p.maxLength ?? 128),
    upper: p.upper ?? true,
    lower: p.lower ?? true,
    number: p.number ?? true,
    symbol: p.symbol ?? true,
    forbidCommon: p.forbidCommon ?? true
  };
}

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`valida-br-api rodando em http://localhost:${PORT}`);
});
