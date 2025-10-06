import { Link } from 'react-router-dom';
import './ArticleCard.css';

function ArticleCard({ article }) {
  return (
    <article className="article-card">
      <div className="article-image">
        <img src={article.image} alt={article.title} />
        <span className="article-category">{article.category}</span>
      </div>
      <div className="article-content">
        <h2 className="article-title">
          <Link to={`/article/${article.slug}`}>{article.title}</Link>
        </h2>
        <p className="article-excerpt">{article.excerpt}</p>
        <div className="article-meta">
          <span className="article-author">👤 {article.author}</span>
          <span className="article-read-time">⏱️ {article.readTime} min</span>
        </div>
        <Link to={`/article/${article.slug}`} className="read-more">
          Baca Selengkapnya →
        </Link>
      </div>
    </article>
  );
}

export default ArticleCard;
