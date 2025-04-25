export interface Env {
	DB: D1Database;
  }

  const corsHeaders = (origin: string) => ({
	'Access-Control-Allow-Origin': origin, // Asigna dinámicamente el valor de 'Origin'
	'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
	'Access-Control-Allow-Headers': 'Content-Type',
	'Access-Control-Allow-Credentials': 'true', // Si necesitas manejar credenciales, puedes habilitar esto
  });

  async function parseJSON(request: Request) {
	try {
	  return await request.json();
	} catch {
	  return null;
	}
  }

  async function sha256Twice(text: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(text);

	const firstHash = await crypto.subtle.digest('SHA-256', data);
	const secondHash = await crypto.subtle.digest('SHA-256', firstHash);

	return Array.from(new Uint8Array(secondHash))
	  .map(b => b.toString(16).padStart(2, '0'))
	  .join('');
  }

  function notAllowed(method: string, path: string, origin: string) {
	return new Response(JSON.stringify({
	  error: 'Method Not Allowed',
	  method,
	  path
	}), { status: 405, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } });
  }

  async function handleCRUD(request: Request, env: Env, pathname: string, method: string, table: string, origin: string): Promise<Response> {
	const idMatch = pathname.match(new RegExp(`^/api/v1/${table}/(\\d+)$`));
	const id = idMatch ? idMatch[1] : null;
	const isUsuarios = table === 'usuarios';

	switch (method) {
	  case 'GET':
		if (id) {
		  const result = await env.DB.prepare(`SELECT * FROM ${table} WHERE id = ?`).bind(id).first();
		  if (!result) return new Response(`${table.slice(0, -1)} no encontrado`, { status: 404, headers: corsHeaders(origin) });
		  return Response.json(result, { headers: corsHeaders(origin) });
		} else {
		  const result = await env.DB.prepare(`SELECT * FROM ${table}`).all();
		  return Response.json(result, { headers: corsHeaders(origin) });
		}

	  case 'POST': {
		const body = await parseJSON(request);
		if (!body) return new Response('JSON inválido', { status: 400, headers: corsHeaders(origin) });

		if (isUsuarios) {
		  if (!body.usuario || !body.contrasena)
			return new Response('Usuario y contraseña son requeridos', { status: 400, headers: corsHeaders(origin) });

		  const hash = await sha256Twice(body.contrasena);
		  const result = await env.DB.prepare(
			'INSERT INTO usuarios (usuario, contrasena) VALUES (?, ?)'
		  ).bind(body.usuario, hash).run();

		  return Response.json({ message: 'Usuario creado', id: result.meta.last_row_id }, { status: 201, headers: corsHeaders(origin) });
		}

		if (!body.titulo || !body.cuerpo || !body.autor)
		  return new Response('Campos obligatorios faltantes', { status: 400, headers: corsHeaders(origin) });

		const result = await env.DB.prepare(
		  `INSERT INTO ${table} (titulo, cuerpo, autor) VALUES (?, ?, ?)`
		).bind(body.titulo, body.cuerpo, body.autor).run();

		return Response.json({ message: `${table.slice(0, -1)} creado`, id: result.meta.last_row_id }, { status: 201, headers: corsHeaders(origin) });
	  }

	  case 'PUT': {
		if (!id) return new Response('ID requerido', { status: 400, headers: corsHeaders(origin) });
		const body = await parseJSON(request);
		if (!body) return new Response('JSON inválido', { status: 400, headers: corsHeaders(origin) });

		if (isUsuarios) {
		  if (!body.usuario || !body.contrasena)
			return new Response('Usuario y contraseña requeridos', { status: 400, headers: corsHeaders(origin) });

		  const hash = await sha256Twice(body.contrasena);
		  await env.DB.prepare(
			'UPDATE usuarios SET usuario = ?, contrasena = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
		  ).bind(body.usuario, hash, id).run();

		  return new Response('Usuario actualizado', { status: 200, headers: corsHeaders(origin) });
		}

		if (!body.titulo || !body.cuerpo || !body.autor)
		  return new Response('Campos obligatorios faltantes', { status: 400, headers: corsHeaders(origin) });

		await env.DB.prepare(
		  `UPDATE ${table} SET titulo = ?, cuerpo = ?, autor = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
		).bind(body.titulo, body.cuerpo, body.autor, id).run();

		return new Response(`${table.slice(0, -1)} actualizado`, { status: 200, headers: corsHeaders(origin) });
	  }

	  case 'DELETE':
		if (!id) return new Response('ID requerido', { status: 400, headers: corsHeaders(origin) });
		await env.DB.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id).run();
		return new Response(`${table.slice(0, -1)} eliminado`, { status: 200, headers: corsHeaders(origin) });

	  default:
		return notAllowed(method, pathname, origin);
	}
  }

  export default {
	async fetch(request: Request, env: Env): Promise<Response> {
	  const url = new URL(request.url);
	  const pathname = url.pathname;
	  const method = request.method;
	  const origin = request.headers.get('Origin') || '*'; // Captura el origen de la solicitud o '*'

	  try {
		// CORS preflight (OPTIONS request)
		if (method === 'OPTIONS') {
		  return new Response(null, {
			status: 204,
			headers: corsHeaders(origin)
		  });
		}

		if (pathname === '/api/v1/crear-tablas' && method === 'POST') {
		  const sql = `
			CREATE TABLE IF NOT EXISTS actas (
			  id INTEGER PRIMARY KEY AUTOINCREMENT,
			  titulo TEXT NOT NULL,
			  cuerpo TEXT NOT NULL,
			  autor TEXT NOT NULL,
			  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			  status TEXT DEFAULT 'activo'
			);
			CREATE TABLE IF NOT EXISTS circulares (
			  id INTEGER PRIMARY KEY AUTOINCREMENT,
			  titulo TEXT NOT NULL,
			  cuerpo TEXT NOT NULL,
			  autor TEXT NOT NULL,
			  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			  status TEXT DEFAULT 'activo'
			);
			CREATE TABLE IF NOT EXISTS usuarios (
			  id INTEGER PRIMARY KEY AUTOINCREMENT,
			  usuario TEXT NOT NULL UNIQUE,
			  contrasena TEXT NOT NULL,
			  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			  status TEXT DEFAULT 'activo'
			);
		  `;
		  await env.DB.prepare(sql).run();
		  return new Response('Tablas creadas o ya existen.', { status: 200, headers: corsHeaders(origin) });
		}

		if (pathname.startsWith('/api/v1/actas')) {
		  return await handleCRUD(request, env, pathname, method, 'actas', origin);
		}

		if (pathname.startsWith('/api/v1/circulares')) {
		  return await handleCRUD(request, env, pathname, method, 'circulares', origin);
		}

		if (pathname.startsWith('/api/v1/usuarios')) {
		  return await handleCRUD(request, env, pathname, method, 'usuarios', origin);
		}

		return new Response(JSON.stringify({
		  error: 'Ruta no encontrada',
		  method,
		  pathname,
		  url: request.url
		}), { status: 404, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } });
	  } catch (error: any) {
		return new Response(JSON.stringify({
		  error: error.message,
		  method,
		  pathname,
		  url: request.url
		}), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } });
	  }
	}
  };
