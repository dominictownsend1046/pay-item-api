#!/usr/bin/env node
const bcrypt = require('bcrypt');
const prisma = require('../db/client');

(async () => {
  const username = process.env.SEED_ADMIN_USER || 'admin';
  const password = process.env.SEED_ADMIN_PASS;
  if (!password) {
    console.error('ERROR: Set SEED_ADMIN_PASS to run this script safely.');
    process.exit(1);
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const user = await prisma.user.upsert({
    where: { username },
    update: {},
    create: { username, passwordHash, role: 'admin' }
  });
  console.log('Admin ready:', user.username);
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
