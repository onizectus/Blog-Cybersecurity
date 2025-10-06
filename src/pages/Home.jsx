import { useState } from 'react';
import ArticleCard from '../components/ArticleCard';
import { articles, categories } from '../data/articles';
import './Home.css';

function Home() {
  const [selectedCategory, setSelectedCategory] = useState('Semua');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredArticles = articles.filter(article => {
    const matchesCategory = selectedCategory === 'Semua' || article.category === selectedCategory;
    const matchesSearch = article.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         article.excerpt.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="home">
      <section className="hero">
        <div className="container">
          <h1 className="hero-title">
            <span className="highlight">Cybersecurity</span> Lab Documentation
          </h1>
          <p className="hero-subtitle">
            Dokumentasi eksperimen penetration testing, vulnerability assessment, dan network security monitoring oleh Lubellion
          </p>
          <div className="hero-stats">
                        <div className="stat">
              <span className="stat-number">{articles.length}</span>
              <span className="stat-label">Lab Reports</span>
            </div>
            <div className="stat">
              <span className="stat-number">3</span>
              <span className="stat-label">Experiments</span>
            </div>
            <div className="stat">
              <span className="stat-number">100%</span>
              <span className="stat-label">Documented</span>
            </div>
          </div>
        </div>
      </section>

      <section className="filters container">
        <div className="search-box">
          <input
            type="text"
            placeholder="🔍 Search lab reports..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
        <div className="category-filters">
          {categories.map(category => (
            <button
              key={category}
              className={`category-btn ${selectedCategory === category ? 'active' : ''}`}
              onClick={() => setSelectedCategory(category)}
            >
              {category}
            </button>
          ))}
        </div>
      </section>

      <section className="articles container" id="articles">
        {filteredArticles.length > 0 ? (
          <div className="articles-grid">
            {filteredArticles.map(article => (
              <ArticleCard key={article.id} article={article} />
            ))}
          </div>
        ) : (
          <div className="no-results">
            <p>Tidak ada artikel yang ditemukan.</p>
          </div>
        )}
      </section>
    </div>
  );
}

export default Home;
