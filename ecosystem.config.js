module.exports = {
  apps : [
    {
      name: "racopub-auth",
      script: "bin/www",
      watch: true,
      env: {
        "PORT": 3001,
        "NODE_ENV": "development"
      },
      env_production: {
        "PORT": 443,
        "NODE_ENV": "production",
      }
    }
  ]
}
