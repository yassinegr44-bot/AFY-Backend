import { initTRPC, TRPCError } from "@trpc/server";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { q } from "./db.js";
import { authenticate, currentUser, requireAdmin, requireUser } from "./auth.js";
import type { Request } from "express";

const t = initTRPC.context<{req: Request}>().create();
const publicProcedure = t.procedure;
const protectedProcedure = publicProcedure.use(({ctx,next}) => {
  try { requireUser(ctx.req); return next(); }
  catch { throw new TRPCError({code:"UNAUTHORIZED"}); }
});
const adminProcedure = protectedProcedure.use(({ctx,next}) => {
  try { requireAdmin(ctx.req); return next(); }
  catch { throw new TRPCError({code:"FORBIDDEN"}); }
});
const id = z.coerce.number().int().positive();

async function audit(req: Request, action: string, extra: any = {}) {
  const u = currentUser(req);
  await q("INSERT INTO audit(user_id,user_name,role,action,deces_id,deces_numero,details) VALUES(?,?,?,?,?,?,?)",
    [u?.id||null,u?.displayName||null,u?.role||null,action,extra.decesId||null,extra.decesNumero||null,JSON.stringify(extra)]);
}

const userInput = z.object({
  username:z.string().min(1), displayName:z.string().min(1),
  password:z.string().min(1).optional(), role:z.enum(["ADMIN","AGENT"]).default("AGENT"),
  active:z.boolean().default(true)
});

export const appRouter = t.router({
  auth: t.router({
    login: publicProcedure.input(z.object({username:z.string(),password:z.string()})).mutation(async ({input,ctx})=>{
      const user = await authenticate(input.username,input.password);
      if (!user) throw new TRPCError({code:"UNAUTHORIZED",message:"Identifiants invalides"});
      (ctx.req.session as any).user=user; await audit(ctx.req,"CONNEXION"); return user;
    }),
    me: publicProcedure.query(({ctx})=>currentUser(ctx.req)),
    logout: protectedProcedure.mutation(async ({ctx})=>{ await audit(ctx.req,"DECONNEXION"); ctx.req.session.destroy(()=>{}); return {ok:true}; }),
    changePassword: protectedProcedure.input(z.object({oldPassword:z.string(),newPassword:z.string().min(6)})).mutation(async ({input,ctx})=>{
      const u=requireUser(ctx.req); const rows=await q<any[]>("SELECT password_hash FROM users WHERE id=?", [u.id]);
      if(!rows[0] || !(await bcrypt.compare(input.oldPassword,rows[0].password_hash))) throw new TRPCError({code:"BAD_REQUEST",message:"Ancien mot de passe incorrect"});
      await q("UPDATE users SET password_hash=? WHERE id=?", [await bcrypt.hash(input.newPassword,12),u.id]); return {ok:true};
    })
  }),
  deces: t.router({
    create: protectedProcedure.input(z.any()).mutation(async ({input,ctx})=>{
      const x=input as any; const numero=x.numero || `AFY-${Date.now()}`;
      const r:any=await q("INSERT INTO deces(numero,anonyme,nom,prenom,cin,sexe,age_inconnu,age,date_entree,service_origine,mode_arrivee,frigo_id,observations_entree,agent_entree_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [numero,!!x.anonyme,x.nom||null,x.prenom||null,x.cin||null,x.sexe||"INDETERMINE",!!x.ageInconnu,x.age??null,x.dateEntree?new Date(x.dateEntree):new Date(),x.serviceOrigine||null,x.modeArrivee||null,x.frigoId||null,x.observationsEntree||null,requireUser(ctx.req).id]);
      await audit(ctx.req,"CREATION_DOSSIER",{decesId:r.insertId,decesNumero:numero}); return {id:r.insertId,numero};
    }),
    list: protectedProcedure.input(z.any().optional()).query(async ({input})=>{
      const x:any=input||{}; let sql="SELECT d.*,f.code frigo_code FROM deces d LEFT JOIN frigos f ON f.id=d.frigo_id WHERE 1=1"; const p:any[]=[];
      if(x.archive!==undefined){sql+=" AND d.archive=?";p.push(!!x.archive)} if(x.statut){sql+=" AND d.statut=?";p.push(x.statut)}
      sql+=" ORDER BY d.date_entree DESC"; return q(sql,p);
    }),
    get: protectedProcedure.input(z.object({id})).query(async ({input})=>{ const r=await q<any[]>("SELECT d.*,f.code frigo_code FROM deces d LEFT JOIN frigos f ON f.id=d.frigo_id WHERE d.id=?",[input.id]); if(!r[0]) throw new TRPCError({code:"NOT_FOUND"}); return r[0]; }),
    update: protectedProcedure.input(z.object({id}).passthrough()).mutation(async ({input,ctx})=>{
      const x:any=input; const allowed:any={"numero":"numero","anonyme":"anonyme","nom":"nom","prenom":"prenom","cin":"cin","sexe":"sexe","ageInconnu":"age_inconnu","age":"age","dateEntree":"date_entree","serviceOrigine":"service_origine","modeArrivee":"mode_arrivee","frigoId":"frigo_id","observationsEntree":"observations_entree"};
      const sets:string[]=[]; const p:any[]=[]; for(const [k,col] of Object.entries(allowed)){if(x[k]!==undefined){sets.push(`${col}=?`);p.push(x[k] instanceof Date?x[k]:x[k]);}} if(!sets.length)return {ok:true}; p.push(x.id); await q(`UPDATE deces SET ${sets.join(",")} WHERE id=?`,p); await audit(ctx.req,"MODIFICATION_DOSSIER",{decesId:x.id}); return {ok:true};
    }),
    enregistrerSortie: protectedProcedure.input(z.object({id}).passthrough()).mutation(async ({input,ctx})=>{
      const x:any=input; await q("UPDATE deces SET statut='SORTI',date_sortie=?,destination=?,ambulance=?,numero_inhumation=?,observations_sortie=?,agent_sortie_id=? WHERE id=?",
      [x.dateSortie?new Date(x.dateSortie):new Date(),x.destination||null,x.ambulance||null,x.numeroInhumation||null,x.observationsSortie||null,requireUser(ctx.req).id,x.id]); await audit(ctx.req,"SORTIE",{decesId:x.id}); return {ok:true};
    }),
    archiver: protectedProcedure.input(z.object({id,archive:z.boolean().default(true)})).mutation(async ({input,ctx})=>{await q("UPDATE deces SET archive=? WHERE id=?",[input.archive,input.id]);await audit(ctx.req,input.archive?"ARCHIVAGE":"DESARCHIVAGE",{decesId:input.id});return {ok:true};})
  }),
  priseEnCharge: t.router({
    upsert: protectedProcedure.input(z.object({decesId:id}).passthrough()).mutation(async ({input,ctx})=>{
      const x:any=input; await q(`INSERT INTO prise_en_charge(deces_id,type,nom_responsable,date_prise_en_charge,contact,observations,statut) VALUES(?,?,?,?,?,?,?)
        ON DUPLICATE KEY UPDATE type=VALUES(type),nom_responsable=VALUES(nom_responsable),date_prise_en_charge=VALUES(date_prise_en_charge),contact=VALUES(contact),observations=VALUES(observations),statut=VALUES(statut)`,
      [x.decesId,x.type||"NON_DEFINIE",x.nomResponsable||null,x.datePriseEnCharge?new Date(x.datePriseEnCharge):null,x.contact||null,x.observations||null,x.statut||"A_DEFINIR"]); await audit(ctx.req,"PRISE_EN_CHARGE",{decesId:x.decesId}); return {ok:true};
    })
  }),
  frigos: t.router({
    list: protectedProcedure.query(async()=>q("SELECT f.*,COALESCE(x.occupees,0) occupees,GREATEST(f.capacite-COALESCE(x.occupees,0),0) disponibles FROM frigos f LEFT JOIN (SELECT frigo_id,COUNT(*) occupees FROM deces WHERE statut='PRESENT' AND archive=0 GROUP BY frigo_id) x ON x.frigo_id=f.id ORDER BY f.code")),
    create: adminProcedure.input(z.any()).mutation(async ({input})=>{const x:any=input;const r:any=await q("INSERT INTO frigos(code,capacite,etat,observations) VALUES(?,?,?,?)",[x.code,x.capacite||10,x.etat||"FONCTIONNEL",x.observations||null]);return {id:r.insertId}}),
    update: adminProcedure.input(z.object({id}).passthrough()).mutation(async({input})=>{const x:any=input;const cols:any={code:"code",capacite:"capacite",etat:"etat",derniereVerification:"derniere_verification",derniereMaintenance:"derniere_maintenance",prochaineMaintenance:"prochaine_maintenance",observations:"observations"};const s:string[]=[];const p:any[]=[];for(const[k,c]of Object.entries(cols)){if(x[k]!==undefined){s.push(`${c}=?`);p.push(x[k])}}if(s.length){p.push(x.id);await q(`UPDATE frigos SET ${s.join(",")} WHERE id=?`,p)}return{ok:true}})
  }),
  materiels: t.router({
    list: protectedProcedure.query(()=>q("SELECT * FROM materiels ORDER BY nom")),
    create: adminProcedure.input(z.any()).mutation(async({input})=>{const x:any=input;const r:any=await q("INSERT INTO materiels(nom,type,reference,frigo_id,statut,observations) VALUES(?,?,?,?,?,?)",[x.nom,x.type||null,x.reference||null,x.frigoId||null,x.statut||"FONCTIONNEL",x.observations||null]);return{id:r.insertId}}),
    update: adminProcedure.input(z.object({id}).passthrough()).mutation(async({input})=>{const x:any=input;const cols:any={nom:"nom",type:"type",reference:"reference",frigoId:"frigo_id",statut:"statut",dateMiseService:"date_mise_service",derniereMaintenance:"derniere_maintenance",prochaineMaintenance:"prochaine_maintenance",probleme:"probleme",dateIntervention:"date_intervention",responsableIntervention:"responsable_intervention",resultatIntervention:"resultat_intervention",observations:"observations"};const s:string[]=[];const p:any[]=[];for(const[k,c]of Object.entries(cols)){if(x[k]!==undefined){s.push(`${c}=?`);p.push(x[k])}}if(s.length){p.push(x.id);await q(`UPDATE materiels SET ${s.join(",")} WHERE id=?`,p)}return{ok:true}}),
    declarerPanne: adminProcedure.input(z.object({id}).passthrough()).mutation(async({input,ctx})=>{const x:any=input;await q("UPDATE materiels SET statut='EN_PANNE',probleme=? WHERE id=?",[x.probleme||null,x.id]);await audit(ctx.req,"DECLARATION_PANNE");return{ok:true}})
  }),
  stats: t.router({
    dashboard: protectedProcedure.query(async()=>{const r:any[]=await q("SELECT COUNT(*) total, SUM(statut='PRESENT' AND archive=0) presents,SUM(statut='SORTI') sorties,SUM(statut='PRESENT' AND archive=0 AND DATEDIFF(NOW(),date_entree)>=15) alertes FROM deces");return r[0]}),
    alertes: protectedProcedure.query(()=>q("SELECT * FROM deces WHERE statut='PRESENT' AND archive=0 AND DATEDIFF(NOW(),date_entree)>=15 ORDER BY date_entree")),
    statistiques: protectedProcedure.query(async()=>{const [s,sex,fr]=await Promise.all([q("SELECT statut,COUNT(*) count FROM deces GROUP BY statut"),q("SELECT sexe,COUNT(*) count FROM deces GROUP BY sexe"),q("SELECT f.code,COUNT(d.id) occupees,f.capacite FROM frigos f LEFT JOIN deces d ON d.frigo_id=f.id AND d.statut='PRESENT' AND d.archive=0 GROUP BY f.id")]);return{statuts:s,sexes:sex,frigos:fr}})
  }),
  users: t.router({
    list: adminProcedure.query(()=>q("SELECT id,username,display_name displayName,role,active,created_at createdAt FROM users ORDER BY username")),
    create: adminProcedure.input(userInput).mutation(async({input,ctx})=>{const x:any=input;if(!x.password)throw new TRPCError({code:"BAD_REQUEST",message:"password requis"});const r:any=await q("INSERT INTO users(username,display_name,password_hash,role,active) VALUES(?,?,?,?,?)",[x.username,x.displayName,await bcrypt.hash(x.password,12),x.role,!!x.active]);await audit(ctx.req,"CREATION_UTILISATEUR");return{id:r.insertId}}),
    update: adminProcedure.input(z.object({id}).passthrough()).mutation(async({input})=>{const x:any=input;const sets:string[]=[];const p:any[]=[];if(x.displayName!==undefined){sets.push("display_name=?");p.push(x.displayName)}if(x.role!==undefined){sets.push("role=?");p.push(x.role)}if(x.active!==undefined){sets.push("active=?");p.push(!!x.active)}if(x.password){sets.push("password_hash=?");p.push(await bcrypt.hash(x.password,12))}if(sets.length){p.push(x.id);await q(`UPDATE users SET ${sets.join(",")} WHERE id=?`,p)}return{ok:true}})
  }),
  parametres: t.router({
    get: protectedProcedure.query(()=>q("SELECT cle,valeur FROM parametres")),
    set: adminProcedure.input(z.object({cle:z.string(),valeur:z.string()})).mutation(async({input})=>{await q("INSERT INTO parametres(cle,valeur) VALUES(?,?) ON DUPLICATE KEY UPDATE valeur=VALUES(valeur)",[input.cle,input.valeur]);return{ok:true}})
  }),
  audit: t.router({
    list: adminProcedure.input(z.any().optional()).query(async({input})=>{const x:any=input||{};let sql="SELECT * FROM audit ORDER BY created_at DESC LIMIT 500";return q(sql)})
  })
});
export type AppRouter = typeof appRouter;
