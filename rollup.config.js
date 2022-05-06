import copy from 'rollup-plugin-copy';
import typescript from '@rollup/plugin-typescript';


export default [
    {
        input: 'src/index.ts',
        output: {
            dir: './dist',
            format: 'es'
        },
        plugins: [
            typescript(), copy({
                targets: [
                    { src: 'src/index.d.ts', dest: 'dist/' },
                ]
            })
        ]
    }
];