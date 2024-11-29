import sqlQuestFactory, { SqlQuest } from '@bitreel/sql-quest';
import Deasyncify from 'deasyncify';
import * as process from 'process';
import { configDotenv } from 'dotenv';
import { log } from 'console';

configDotenv();

export const sqlQuest: SqlQuest = sqlQuestFactory({
  databaseUrl: process.env.DATABASE_URL as string,
});

let retry = 3;

export async function connectDB(): Promise<SqlQuest> {

  const [, err] = await Deasyncify.watch(sqlQuest.connect());

  if (err != null) {
    console.log(err);
    if (retry > 0) {
      log(`Error connecting to database, retrying... (${retry} left)`);
      retry -= 1;
      await connectDB();
    }

    process.exit(1);
  }

  log('Connected to postgres database');

  return sqlQuest;
}
