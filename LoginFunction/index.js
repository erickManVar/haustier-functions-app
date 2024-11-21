const sql = require('mssql');
require('dotenv').config();

module.exports = async function (context, req) {
    const { email, contraseña } = req.body;

    // Verificar si los parámetros están presentes
    if (!email || !contraseña) {
        context.res = {
            status: 400,
            headers: {
                "Access-Control-Allow-Origin": "*", // Permitir solicitudes desde cualquier origen
                "Access-Control-Allow-Methods": "POST, OPTIONS", // Métodos permitidos
                "Access-Control-Allow-Headers": "Content-Type" // Encabezados permitidos
            },
            body: 'Por favor, proporcione email y contraseña.'
        };
        return;
    }

    try {
        // Configuración de la conexión a la base de datos
        const config = {
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            server: process.env.DB_SERVER, // Por ejemplo: hogarmaestroserver.database.windows.net
            database: process.env.DB_NAME,
            options: {
                encrypt: true
            }
        };

        // Conectar a la base de datos
        await sql.connect(config);

        // Obtener el hash de la contraseña proporcionada
        const contraseñaHash = (await sql.query`
            SELECT CONVERT(NVARCHAR(256), HASHBYTES('SHA2_256', ${contraseña}), 1) AS Hash
        `).recordset[0].Hash;

        // Consultar el usuario en la base de datos
        const result = await sql.query`
            SELECT UsuarioID, NombreUsuario, Email, Rol
            FROM Usuario
            WHERE Email = ${email} AND ContraseñaHash = ${contraseñaHash}
        `;

        if (result.recordset.length > 0) {
            const usuario = result.recordset[0];

            // Respuesta con datos del usuario
            context.res = {
                status: 200,
                headers: {
                    "Access-Control-Allow-Origin": "*", // Permitir solicitudes desde cualquier origen
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                },
                body: {
                    mensaje: 'Inicio de sesión exitoso',
                    usuario: {
                        id: usuario.UsuarioID,
                        nombre: usuario.NombreUsuario,
                        email: usuario.Email,
                        rol: usuario.Rol
                    }
                }
            };
        } else {
            // Credenciales incorrectas
            context.res = {
                status: 401,
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                },
                body: 'Email o contraseña incorrectos.'
            };
        }

        // Cerrar la conexión
        sql.close();
    } catch (err) {
        // Manejar errores
        context.log.error('Error en la función de login:', err);
        context.res = {
            status: 500,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            },
            body: 'Error interno del servidor.'
        };
    }
};
