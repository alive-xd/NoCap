import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default {
  test: {
    exclude: ['node_modules', 'e2e/**'],
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
    coverage: {
      provider: 'v8',
      include: [
        'src/lib/analyzers/**',
        'src/lib/parsers/**',
        'src/lib/investigation/**',
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80
      }
    }
  },
};
