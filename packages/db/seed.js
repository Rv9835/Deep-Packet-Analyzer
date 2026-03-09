import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Seeding database...');

  // Create a test user
  const testUser = await prisma.user.upsert({
    where: { email: 'test@example.com' },
    update: {},
    create: {
      email: 'test@example.com',
      name: 'Test User',
      role: 'USER',
      // In production, use proper password hashing
      password: 'hashed_password_here',
    },
  });

  console.log(`✓ Created test user: ${testUser.email}`);

  // Create a test project
  const testProject = await prisma.project.upsert({
    where: { id: 'test-project-1' },
    update: {},
    create: {
      id: 'test-project-1',
      userId: testUser.id,
      name: 'Test Project',
      description: 'A test project for DPA',
      isActive: true,
    },
  });

  console.log(`✓ Created test project: ${testProject.name}`);

  // Create a test ruleset
  const testRuleset = await prisma.ruleset.upsert({
    where: { id: 'test-ruleset-1' },
    update: {},
    create: {
      id: 'test-ruleset-1',
      projectId: testProject.id,
      name: 'Test Ruleset',
      description: 'A test ruleset',
      rules: JSON.stringify([
        {
          id: 'rule-1',
          name: 'HTTP Detection',
          protocol: 'HTTP',
          pattern: 'GET|POST',
          severity: 'medium',
        },
        {
          id: 'rule-2',
          name: 'HTTPS Detection',
          protocol: 'HTTPS',
          pattern: 'TLS_HANDSHAKE',
          severity: 'low',
        },
      ]),
      isActive: true,
    },
  });

  console.log(`✓ Created test ruleset: ${testRuleset.name}`);

  // Create a test subscription
  const testSubscription = await prisma.subscription.upsert({
    where: { projectId: testProject.id },
    update: {},
    create: {
      projectId: testProject.id,
      plan: 'STARTER',
      status: 'ACTIVE',
      jobsPerMonth: 100,
      fileSize: 524288000, // 500MB
      storageGb: 10,
      billingPeriodStart: new Date(),
      billingPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    },
  });

  console.log(`✓ Created test subscription: ${testSubscription.plan}`);

  // Create associated usage record
  const testUsage = await prisma.usage.upsert({
    where: { subscriptionId: testSubscription.id },
    update: {},
    create: {
      subscriptionId: testSubscription.id,
      jobsUsed: 5,
      storageUsed: 104857600, // 100MB
      periodStart: testSubscription.billingPeriodStart!,
      periodEnd: testSubscription.billingPeriodEnd!,
    },
  });

  console.log(`✓ Created test usage record`);

  // Create an API key for the user
  const testApiKey = await prisma.apiKey.upsert({
    where: { id: 'test-api-key-1' },
    update: {},
    create: {
      id: 'test-api-key-1',
      userId: testUser.id,
      name: 'Test API Key',
      token: 'dpa_test_key_abc123def456', // In production, this should be hashed
      isRevoked: false,
    },
  });

  console.log(`✓ Created test API key: ${testApiKey.name}`);

  console.log('✅ Database seeding complete!');
}

main()
  .catch((e) => {
    console.error('❌ Seed error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
