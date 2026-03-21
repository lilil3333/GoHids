/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0D1117',        // 主背景
          surface: '#161B22',   // 卡片/表格行背景
          elevated: '#21262D',  // 悬浮层
          border: '#30363D',    // 边框
          text: {
            primary: '#C9D1D9',   // 主要文字
            secondary: '#8B949E', // 次要文字
            muted: '#6E7681',     // 禁用/时间戳
          },
          status: {
            critical: '#FF4D4F',  // 高危红色(霓虹感)
            warning: '#FAAD14',   // 可疑橙色
            safe: '#238636',      // 安全绿色(矩阵绿)
            info: '#58A6FF',      // 系统蓝色
            processing: '#39D353' // 实时脉冲绿
          }
        }
      },
      fontFamily: {
        sans: ['Inter', 'Noto Sans SC', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-fast': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 2s linear infinite',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        }
      }
    },
  },
  plugins: [],
}
