const { Worker } = require('bullmq');

new Worker('emails', async (job) => {
  return job.data;
});
