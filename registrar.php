<?php
// Mostrar errores en desarrollo; en producción quita o regístralos en log
ini_set('display_errors', 1);
error_reporting(E_ALL);

// 1. Parámetros de conexión MySQL
$host = 'localhost';
$user = 'root';
$pass = '';  // si Laragon usa contraseña, ponla aquí
$db   = 'exponentiallongterm';

// 2. Conectar a MySQL
$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die("<p class='error'>Error de conexión: " . htmlspecialchars($conn->connect_error) . "</p>");
}
$conn->set_charset('utf8mb4');

// 3. Recoger y sanitizar datos POST
$nombre = isset($_POST['nombre_completo']) ? trim($_POST['nombre_completo']) : '';
$edad_raw = isset($_POST['edad']) ? $_POST['edad'] : '';
$correo = isset($_POST['correo']) ? trim($_POST['correo']) : '';
$genero = isset($_POST['genero']) ? $_POST['genero'] : '';
$contrasena_raw = isset($_POST['contrasena']) ? $_POST['contrasena'] : '';

// 4. Validaciones básicas
$errores = [];
if ($nombre === '') {
    $errores[] = "El nombre completo es obligatorio.";
}
if ($edad_raw === '' || !is_numeric($edad_raw) || intval($edad_raw) <= 0) {
    $errores[] = "La edad debe ser un número mayor que cero.";
} else {
    $edad = intval($edad_raw);
}
if ($correo === '' || !filter_var($correo, FILTER_VALIDATE_EMAIL)) {
    $errores[] = "Correo electrónico inválido o vacío.";
}
$opciones_genero = ['Masculino', 'Femenino', 'Prefiero no decirlo'];
if ($genero === '' || !in_array($genero, $opciones_genero, true)) {
    $errores[] = "Debes seleccionar un género válido.";
}
if ($contrasena_raw === '' || strlen($contrasena_raw) < 8) {
    $errores[] = "La contraseña es obligatoria y debe tener al menos 8 caracteres.";
}

if (!empty($errores)) {
    echo "<div class='error'><ul>";
    foreach ($errores as $e) {
        echo "<li>" . htmlspecialchars($e) . "</li>";
    }
    echo "</ul></div>";
    echo "<p><a href='Registro.html'>Volver al formulario</a></p>";
    exit;
}

// 5. Escapar datos
$nombre_safe = $conn->real_escape_string($nombre);
$correo_safe = $conn->real_escape_string($correo);
$genero_safe = $conn->real_escape_string($genero);

// 6. Verificar duplicado de correo
$stmt = $conn->prepare("SELECT id FROM usuarios WHERE correo = ?");
if (!$stmt) {
    die("<p class='error'>Error en prepare(): " . htmlspecialchars($conn->error) . "</p>");
}
$stmt->bind_param("s", $correo_safe);
$stmt->execute();
$stmt->store_result();
if ($stmt->num_rows > 0) {
    echo "<p class='error'>Ya existe una cuenta con ese correo.</p>";
    echo "<p><a href='Registro.html'>Volver al formulario</a></p>";
    $stmt->close();
    $conn->close();
    exit;
}
$stmt->close();

// 7. Hashear contraseña
$hash = password_hash($contrasena_raw, PASSWORD_DEFAULT);
if ($hash === false) {
    die("<p class='error'>Error al procesar la contraseña.</p>");
}

// 8. Insertar nuevo registro
$stmt = $conn->prepare(
    "INSERT INTO usuarios (nombre_completo, edad, correo, genero, contrasena) VALUES (?, ?, ?, ?, ?)"
);
if (!$stmt) {
    die("<p class='error'>Error en prepare() de INSERT: " . htmlspecialchars($conn->error) . "</p>");
}
$stmt->bind_param("sisss", $nombre_safe, $edad, $correo_safe, $genero_safe, $hash);
if ($stmt->execute()) {
    // ✅ Redirección tras éxito
    header("Location: sitio.html");
    exit();
} else {
    echo "<p class='error'>Error al registrar: " . htmlspecialchars($stmt->error) . "</p>";
}
$stmt->close();
$conn->close();
?>
