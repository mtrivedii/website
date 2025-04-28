const sql = require("mssql");
const dbConfig = { server:process.env.DB_SERVER, database:process.env.DB_NAME,
  authentication:{type:"azure-active-directory-msi-app-service"},
  options:{ encrypt:true, trustServerCertificate:true,
            multiSubnetFailover:true, connectTimeout:15000, requestTimeout:300000 },
  pool:{ max:10,min:0,idleTimeoutMillis:30000 }
};

let poolPromise=null, poolInstance=null;
async function getPool(){
  console.log("users:getPool: DB_SERVER=%s DB_NAME=%s",process.env.DB_SERVER,process.env.DB_NAME);
  if(poolInstance && poolInstance.connected===false){ console.log("users:pool disconnected→clearing"); poolPromise=null; }
  if(poolPromise){ console.log("users:re-using pool"); return poolPromise; }
  console.log("users:creating new pool");
  const p=new sql.ConnectionPool(dbConfig);
  poolInstance=p;
  p.on("error",e=>{ console.error("users:pool error",e); poolPromise=null; });
  sql.on("error",e=> console.error("users:mssql global error",e));
  poolPromise=p.connect().then(()=>{ console.log("users:pool connected"); return p; })
               .catch(err=>{ console.error("users:connect failed",err); poolPromise=null; poolInstance=null; throw err; });
  return poolPromise;
}

module.exports=async function(context,req){
  const id=context.executionContext.invocationId;
  context.log(`[${id}] users ${req.method}`);
  try{
    const pool=await getPool();
    context.log(`[${id}] users ping SELECT 1`);
    await pool.request().query("SELECT 1");
    context.log(`[${id}] users ping OK`);
    const result=await pool.request().query("SELECT id,email,Role AS role FROM Users");
    context.res={status:200,body:result.recordset};
  }catch(e){
    context.log.error(`[${id}] users ERROR`,e.stack||e);
    context.res={status:500,body:{message:"Internal server error"}};
  }
};
