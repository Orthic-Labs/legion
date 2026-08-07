#!/usr/bin/env node
import { qualifyBook } from './qualify-book.mjs';

const receipt = await qualifyBook(2);
process.stdout.write(`${JSON.stringify(receipt)}\n`);
process.exitCode = receipt.status === 'pass' ? 0 : 1;
