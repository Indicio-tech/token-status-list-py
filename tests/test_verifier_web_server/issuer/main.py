from issuer import TokenStatusListIssuer

MY_HTML = """\
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>My Website</title>
  </head>
  <body>
    <main>
        <h1>This is really my new website.</h1>  
    </main>
  </body>
</html>
"""

if __name__ == "__main__":
    with open("/var/www/html/app.html", "w+") as new_file:
        new_file.write(MY_HTML)