<?php

//Incluir el archivo de conexión
require_once "conexion.php";

//Crear las variables y las inicializamos en vacio

$username = $password = $confirm_password = "";
$username_err =$password_err = $confirm_password_err = "";

//proceso de enviar los datos del formulario a la base de datos 

if($_SERVER["REQUEST_METHOD"]=="POST")
{
    //Validar que el campo Usuario no este vacio
    //trim elimina los espacios en blanco

    if(empty(trim($_POST['usuario'])))
    {
        $username_err="Por favor ingrese un usuario";
    }
    else
    {
        //Crear una consulta de SQL que verifique cuantos usuarios hay con los mismos caracteres, lo almacenamos en una variable.

        $sql="SELECT id FROM registro WHERE usuario = ?";

        //mysqli_prepare es una sentencia de SQL que mejora la seguridad y rendimeinto de la aplicación
        if ($prepare=mysqli_prepare($conexion,$sql))
        {
            mysqli_stmt_bind_param($prepare,"s",$parametro_usuario);
            //mysqli_stmt_bind_param es usada para enlazar variables que envian las consultas de SQL
            
            $parametro_usuario=trim($_POST['usuario']);

            //mysqli_stmt_execute() ejecuta una consulta previamente preparada en mysqli_prepare

            if(mysqli_stmt_execute($prepare))
            {
                mysqli_stmt_store_result($prepare);
                if(mysqli_stmt_num_rows($prepare)==1)
                {
                    $username_err="Este usuario ya esta registrado!!";
                }
                else
                {
                    $username_err="Al parecer algo salio mal";    
                }
            }
            mysqli_stmt_close($prepare);

            //validar la contraseña

            //1 vamos a validar que el campo no este vacio
            if(empty(trim($_POST['clave'])))
                {
                    $password_err="Por favor ingrese una contraseña";
                }
                //2. Validar que almenos tenga 6 caracteres
                else if(strlen(trim($_POST['clave']))<6)
                {
                    $password_err="La contraseña al menos debe tener 6 caracteres.";
                }
                else
                {
                    $password=trim($_POST['clave']);
                }
                //validar el campo confirmar contraseña 
                if(empty(trim($_POST['clave_confirm'])))
                {
                    $confirm_password_err ="Debes validar tu contraseña";
                }
                else
                {
                    $confirm_password=trim($_POST['clave_confirm']);
                    if(empty($password_err) && ($password != $confirm_password))
                    {
                        $confirm_password_err="No coinciden las contraseñas";
                    }
                }   
                //validar que todos los campos de error este vacio  
                if(empty($username_err) && empty($password_err) && empty($confirm_password))
                    {
                        //crear la consulta
                        $sql = "INSERT INTO registro (usario,clave) -VALUES (?,?) ";

                        if($prepare=mysqli_prepare($conexion, $sql))
                        {

                        
                        //INSERT INTO registro (usario,clave) VALUES PERMITE ENVIAR VARIOS VALORES
                        //INSERT INTO registro VALUES SOLO PERMITE ENVIAR DE A UN VALOR

                        mysqli_stmt_bind_param($prepare, "ss", $parametro_usuario, $parametro_clave);

                        //enviarle valores a los parametros
                        $parametro_usuario=$username;
                        $parametro_clave=password_hash($password, PASSWORD_DEFAULT);
                        if(mysqli_stmt_execute($prepare))
                        {
                            header("location:login.php");
                        }
                        else
                        {
                            echo "<script> alert('Algo salio mal, por favor intentarlo de nuevo')";
                        }
                        }

                        mysqli_stmt_close($prepare);

                    }
                    mysqli_close($conexion);
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
    <title>Registro</title>
    <style>
        body
        {
            font: 14px sans-serif;
        }
        .contenedor
        {
            width:350px;
            padding:20px;
        }
    </style>
</head>
<body>
    <div class="contenedor">
        <h2>Registro</h2>
        <p>
            Por favor, Complete este formulario para crear una cuenta.
        </p>
        <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
            <div class= "form-group" <?php echo(!empty($username_err)) ? 'has-error' : ''; ?> > 
            <label for="">Usuario</label>
            <input type="text" name="usuario" class ="form-control" value = " <?php echo $username; ?>">
            <span style="color: red;" > <?php echo $username_err; ?> </span>
            </div>
            <div class= "form-group" <?php echo(!empty($password_err)) ? 'has-error' : ''; ?> > 
            <label for="">Contraseña</label>
            <input type="password" name="clave" class="form-control" value = " <?php echo $password; ?>">
            <span class= "help-block"> <?php echo $password_err; ?> </span>           
            </div>
            <div class="form-group" <?php echo(!empty($confirm_password_err)) ? 'has-error' : ''; ?>>
            <label for="">Confirmar Contraseña</label>
            <input type="password" name="clave_confirm" class="form-control" value = " <?php echo $confirm_password; ?>">
            <span class= "help-block"> <?php echo $confirm_password_err; ?> </span>                   
            </div>
            <div class="form-group">
                <input type="submit" value="Enviar Datos" class="btn btn-outline-primary">
                <input type="reset" value="Borrar Datos" class="btn btn-outline-success">                
            </div>
            <p>¿Ya tienes Cuenta? <a href="login.php">Ingresa aquí</a></p>
        </form>
    </div>
</body>
</html>