function toErrorPayload(error) {
  if (!error) return { message: 'Unknown error' };
  return {
    name: error.name,
    message: error.message,
    stack: error.stack,
  };
}

function emit(level, event, payload = {}) {
  const record = {
    ts: new Date().toISOString(),
    level,
    event,
    ...payload,
  };

  const serialized = JSON.stringify(record);
  if (level === 'error') {
    console.error(serialized);
  } else if (level === 'warn') {
    console.warn(serialized);
  } else {
    console.log(serialized);
  }
}

export function logInfo(event, payload) {
  emit('info', event, payload);
}

export function logWarn(event, payload) {
  emit('warn', event, payload);
}

export function logError(event, payload) {
  emit('error', event, payload);
}

export function withRequest(payload = {}, req) {
  return {
    requestId: req?.requestId || null,
    method: req?.method,
    path: req?.originalUrl,
    ...payload,
  };
}

export function errorPayload(error, includeStack = true) {
  const parsed = toErrorPayload(error);
  if (!includeStack) {
    delete parsed.stack;
  }
  return parsed;
}

