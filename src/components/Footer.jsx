import './Footer.css';

function Footer() {
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-content">
          <div className="footer-section">
            <h3>Cybersecurity Lab Documentation</h3>
            <p>Lab experiments documentation by Lubellion. Dokumentasi penelitian dan eksperimen ethical hacking untuk tujuan edukasi dan penelitian.</p>
          </div>
          <div className="footer-section">
            <h3>Quick Links</h3>
            <ul>
              <li><a href="/">Home</a></li>
              <li><a href="/about">Tentang</a></li>
              <li><a href="#articles">Lab Reports</a></li>
            </ul>
          </div>
          <div className="footer-section">
            <h3>Disclaimer</h3>
            <p>Semua konten di blog ini hanya untuk tujuan edukasi. Gunakan dengan tanggung jawab dan etika.</p>
          </div>
        </div>
        <div className="footer-bottom">
          <p>&copy; 2024 Lubellion's Cybersecurity Lab. All experiments conducted in controlled environment for educational purposes.</p>
        </div>
      </div>
    </footer>
  );
}

export default Footer;
