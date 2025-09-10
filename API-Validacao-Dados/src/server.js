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
    max: 120, // 120 req/min por IP
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
  if (requireSymbol && !/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;/`'~]/.test(s)) errors.push('Ao menos 1 símbolo');

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

  const normalized = `+55 (${ddd}) ${local.length===11 ? `${local[2]}${local[3]}${local[4]}${local[5]}-${local.slice(6)}` : `${local[2]}${local[3]}${local[4]}${local[5]}-${local.slice(6)}`}`;
  return { valid: true, normalized };
}

// CEP
function validateCEP(raw) {
  const digits = onlyDigits(raw);
  if (digits.length !== 8) return { valid: false, errors: ['CEP deve ter 8 dígitos'] };
  const normalized = `${digits.slice(0,5)}-${digits.slice(5)}`;
  return { valid: true, normalized };
}

// Detecta tipo automaticamente
function detectType(value) {
  const v = String(value || '').trim();
  const digits = onlyDigits(v);
  if (/^\d{11}$/.test(digits)) return 'cpf';
  if (/^\d{14}$/.test(digits)) return 'cnpj';
  if (/^\d{8}$/.test(digits)) return 'cep';
  if (/^\d{10,11}$/.test(digits)) return 'phone-br';
  if (/@/.test(v)) return 'email';
  if (/[A-Za-z]/.test(v) && /[0-9]/.test(v) && /[^A-Za-z0-9]/.test(v)) return 'password';
  return null;
}

// Endpoints existentes
app.get('/health', (req, res) => {
  res.json({ status: 'ok', now: new Date().toISOString() });
});

app.get('/validate/cpf', (req, res) => {
  const { value } = req.query;
  const result = validateCPF(value);
  res.json({ type: 'cpf', input: String(value ?? ''), ...result });
});

app.get('/validate/cnpj', (req, res) => {
  const { value } = req.query;
  const result = validateCNPJ(value);
  res.json({ type: 'cnpj', input: String(value ?? ''), ...result });
});

app.get('/validate/email', (req, res) => {
 

