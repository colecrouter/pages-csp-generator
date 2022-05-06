import copy from 'rollup-plugin-copy';
import typescript from '@rollup/plugin-typescript';


export default [
    {
        input: 'src/index.ts',
        output: {
            entryFileNames: 'index.js',
            dir: './dist',
            format: 'es'
        },
        plugins: [
            typescript(), copy({
                targets: [
                    { src: 'src/types.d.ts', dest: 'dist/', rename: 'index.d.ts' },
                ]
            })
        ]
    }
];