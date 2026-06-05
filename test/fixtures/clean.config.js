// A normal, clean config file. inject-guard must NOT flag anything here.
const tailwindcssAnimate = require('tailwindcss-animate');

module.exports = {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,js,vue}'],
  theme: {
    extend: {
      colors: {
        primary: { DEFAULT: '#6b63ff', 500: '#6b63ff', 900: '#302689' },
      },
    },
  },
  plugins: [tailwindcssAnimate],
};
