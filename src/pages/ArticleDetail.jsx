import { useParams, Link } from 'react-router-dom';
import { articles } from '../data/articles';
import ReactMarkdown from 'react-markdown';
import './ArticleDetail.css';

function ArticleDetail() {
  const { slug } = useParams();
  const article = articles.find(a => a.slug === slug);

  if (!article) {
    return (
      <div className="container">
        <div className="not-found">
          <h1>Artikel Tidak Ditemukan</h1>
          <Link to="/" className="back-link">← Kembali ke Home</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="article-detail">
      <div className="article-hero">
        <img src={article.image} alt={article.title} className="article-hero-image" />
        <div className="article-hero-overlay">
          <div className="container">
            <span className="article-category-badge">{article.category}</span>
            <h1 className="article-hero-title">{article.title}</h1>
            <div className="article-hero-meta">
              <span>👤 {article.author}</span>
              <span>⏱️ {article.readTime} menit baca</span>
            </div>
          </div>
        </div>
      </div>

      <article className="article-body container">
        <Link to="/" className="back-link">← Kembali ke Daftar Artikel</Link>
        
        <div className="article-content-wrapper">
          <ReactMarkdown
            components={{
              h1: ({node, ...props}) => <h1 className="content-h1" {...props} />,
              h2: ({node, ...props}) => <h2 className="content-h2" {...props} />,
              h3: ({node, ...props}) => <h3 className="content-h3" {...props} />,
              h4: ({node, ...props}) => <h4 className="content-h4" {...props} />,
              p: ({node, ...props}) => <p className="content-p" {...props} />,
              ul: ({node, ...props}) => <ul className="content-ul" {...props} />,
              ol: ({node, ...props}) => <ol className="content-ol" {...props} />,
              li: ({node, ...props}) => <li className="content-li" {...props} />,
              code: ({node, inline, ...props}) => 
                inline ? 
                  <code className="inline-code" {...props} /> : 
                  <code className="block-code" {...props} />,
              pre: ({node, ...props}) => <pre className="code-block" {...props} />,
              blockquote: ({node, ...props}) => <blockquote className="blockquote" {...props} />,
              a: ({node, ...props}) => <a className="content-link" {...props} target="_blank" rel="noopener noreferrer" />,
            }}
          >
            {article.content}
          </ReactMarkdown>
        </div>

        <div className="article-footer">
          <div className="article-tags">
            <span className="tag">{article.category}</span>
            <span className="tag">Ethical Hacking</span>
            <span className="tag">Cybersecurity</span>
          </div>
          <Link to="/" className="back-to-home">
            ← Lihat Artikel Lainnya
          </Link>
        </div>
      </article>

      <section className="related-articles container">
        <h2>Artikel Terkait</h2>
        <div className="related-grid">
          {articles
            .filter(a => a.id !== article.id && a.category === article.category)
            .slice(0, 3)
            .map(relatedArticle => (
              <Link 
                key={relatedArticle.id} 
                to={`/article/${relatedArticle.slug}`}
                className="related-card"
              >
                <img src={relatedArticle.image} alt={relatedArticle.title} />
                <div className="related-content">
                  <h3>{relatedArticle.title}</h3>
                  <p>{relatedArticle.excerpt.substring(0, 100)}...</p>
                </div>
              </Link>
            ))}
        </div>
      </section>
    </div>
  );
}

export default ArticleDetail;
