const sql = require("mssql"), Joi = require("joi");
const scoreSchema = Joi.object({
  username:Joi.string().alphanum().min(3).max(30).required(),
  score:   Joi.number().integer().min(0).required()
}).options({abortEarly:false});

const dbConfig = { server:process.env.DB_SERVER, database:process.env.DB_NAME,
  authentication:{type:"azure-active-directory-msi-app-service"},
  options:{ encrypt:true,trustServerCertificate:true,
            multiSubnetFailover:true,connectTimeout:15000,requestTimeout:300000 },
  pool:{max:10,min:0,idleTimeoutMillis:30000}
};

let poolPromise=null,poolInstance=null;
async function getPool(){
  console.log("score:getPool: DB_SERVER=%s DB_NAME=%s",process.env.DB_SERVER,process.env.DB_NAME);
  if(poolInstance && poolInstance.connected===false){ console.log("score:pool disconnected→clearing"); poolPromise=null; }
  if(poolPromise){ console.log("score:re-using pool"); return poolPromise; }
  console.log("score:creating new pool");
  const p=new sql.ConnectionPool(dbConfig);
  poolInstance=p;
  p.on("error",e=>{ console.error("score:pool error",e); poolPromise=null; });
  sql.on("error",e=> console.error("score:mssql global error",e));
  poolPromise=p.connect().then(()=>{ console.log("score:pool connected"); return p; })
               .catch(err=>{ console.error("score:connect failed",err); poolPromise=null; poolInstance=null; throw err; });
  return poolPromise;
}

module.exports=async function(context,req){
  const id=context.executionContext.invocationId;
  context.log(`[${id}] scoreboard ${req.method}`);
  try{
    const pool=await getPool();
    context.log(`[${id}] scoreboard ping SELECT 1`);
    await pool.request().query("SELECT 1");
    context.log(`[${id}] scoreboard ping OK`);
    if(req.method==="GET"){
      const r=await pool.request().query("SELECT TOP(10) username,score FROM Scoreboard ORDER BY score DESC");
      context.res={status:200,body:r.recordset}; return;
    }
    if(req.method==="POST"){
      const {error,value}=scoreSchema.validate(req.body);
      if(error){ context.res={status:400,body:{message:error.details.map(d=>d.message).join("; ")}}; return; }
      await pool.request()
        .input("username",sql.NVarChar,value.username)
        .input("score",sql.Int,value.score)
        .query("INSERT INTO Scoreboard(username,score) VALUES(@username,@score)");
      context.res={status:201,body:{message:"Score added"}}; return;
    }
    context.res={status:405,body:"Method Not Allowed"};
  }catch(e){
    context.log.error(`[${id}] scoreboard ERROR`,e.stack||e);
    context.res={status:500,body:{message:"Internal server error"}};
  }
};
