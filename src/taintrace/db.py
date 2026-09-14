"""Known packages database — embedded for offline use."""

from typing import List, Tuple, Dict


class KnownPackagesDB:
    """In-memory database of known legitimate packages."""

    def __init__(self):
        """Load built-in package database."""
        self._packages: Dict[str, set] = {
            "rust": self._RUST_PACKAGES,
            "node": self._NODE_PACKAGES,
            "python": self._PYTHON_PACKAGES,
            "go": self._GO_PACKAGES,
            "ruby": self._RUBY_PACKAGES,
            "php": self._PHP_PACKAGES,
            "swift": self._SWIFT_PACKAGES,
            "elixir": self._ELIXIR_PACKAGES,
            "dart": self._DART_PACKAGES,
        }

    def is_known(self, name: str, ecosystem: str = "rust") -> bool:
        """Check if a package name is in the known packages list."""
        packages = self._packages.get(ecosystem, set())
        return name.lower() in {p.lower() for p in packages}

    def get_similar(self, name: str, threshold: float = 0.8, 
                     ecosystem: str = "rust") -> List[Tuple[str, float]]:
        """Find known packages similar to the given name."""
        from taintrace.similarity import SimilarityEngine
        engine = SimilarityEngine()
        results = []
        packages = self._packages.get(ecosystem, set())
        for known_name in packages:
            score = engine.similarity(name.lower(), known_name.lower())
            if score >= threshold:
                results.append((known_name, score))
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:10]  # Return top 10

    # Built-in package lists (top packages per ecosystem)
    _RUST_PACKAGES = {
        "serde", "tokio", "clap", "reqwest", "actix", "actix-web", "warp",
        "hyper", "rocket", "axum", "sqlx", "diesel", "rusqlite", "redis",
        "chrono", "uuid", "regex", "rand", "log", "env_logger", "anyhow",
        "thiserror", "serde_json", "serde_derive", "proc-macro2", "quote",
        "syn", "libc", "bytes", "futures", "async-trait", "once_cell",
        "parking_lot", "crossbeam", "rayon", "itertools", "bitflags",
        "lazy_static", "http", "tracing", "tower", "pin-project",
        "mio", "rustls", "tokio-util", "async-std", "smol",
        "serde_yaml", "toml", "cargo", "hashbrown", "indexmap",
        "url", "percent-encoding", "unicode-normalization",
        "tracing-subscriber", "tracing-log", "tracing-bunyan",
        "thiserror-impl", "serde", "arrayvec", "smallvec", "heck",
        "cargo_metadata", "gloo", "wasm-bindgen", "js-sys",
        "web-sys", "console_error_panic_hook",
    }

    _NODE_PACKAGES = {
        "react", "vue", "angular", "svelte", "next", "nuxt", "express",
        "lodash", "moment", "axios", "webpack", "vite", "typescript",
        "eslint", "prettier", "jest", "mocha", "chai", "cypress",
        "react-dom", "react-router", "redux", "mobx", "graphql",
        "apollo", "prisma", "sequelize", "typeorm", "mongoose",
        "passport", "jsonwebtoken", "bcrypt", "cors", "dotenv",
        "nodemailer", "multer", "sharp", "socket.io", "uuid",
        "winston", "morgan", "helmet", "compression", "express-rate-limit",
        "jest", "vitest", "ts-node", "tsx", "esbuild", "rollup",
        "babel", "core-js", "regenerator-runtime", "core-js-pure",
        "lodash-es", "ramda", "immutable", "rxjs", "tslib",
        "debug", "ms", "semver", "rimraf", "glob", "minimatch",
    }

    _PYTHON_PACKAGES = {
        "requests", "flask", "django", "fastapi", "pandas", "numpy",
        "scipy", "scikit-learn", "tensorflow", "pytorch", "transformers",
        "pytest", "black", "ruff", "mypy", "isort", "pylint",
        "sphinx", "mkdocs", "jupyter", "matplotlib", "seaborn",
        "sqlalchemy", "alembic", "pydantic", "httpx", "aiohttp",
        "celery", "redis", "boto3", "botocore", "awscli",
        "click", "typer", "rich", "logstructlog", "structlog",
        "python-dateutil", "pytz", "six", "certifi", "charset-normalizer",
        "idna", "urllib3", "packaging", "pyparsing", "tomli",
        "pathlib", "functools", "itertools", "collections",
        "typing-extensions", "annotated-types", "typing-inspection",
        "mcp", "httpx-sse", "pydantic-core", "anyio", "sniffio",
        "h11", "httpcore", "certifi", "click", "rich",
    }

    _GO_PACKAGES = {
        "gin", "echo", "fiber", "chi", "gorilla/mux", "httprouter",
        "gorm", "sqlx", "ent", "migrate", "cobra", "viper",
        "logrus", "zap", "zerolog", "opentelemetry", "prometheus",
        "grpc", "protobuf", "wire", "fx", "testify", "ginkgo",
        "gomega", "gomock", "go-sql-driver/mysql", "go-redis",
        "mongo-go-driver", "aws-sdk-go", "kubernetes/client-go",
        "docker/client", "stretchr/testify", "sirupsen/logrus",
        "pkg/errors", "go-kit/kit", "go-micro",
    }

    # RubyGems all-time top 100 (https://rubygems.org/stats), supplemented
    # with common Rails, testing and tooling gems and their runtime dependencies.
    # Names verified with https://rubygems.org/api/v1/gems/<name>.json.
    _RUBY_PACKAGES = {
        "aasm", "actioncable", "actionmailbox", "actionmailer",
        "actionpack", "actiontext", "actionview", "activeadmin",
        "activejob", "activemodel", "activerecord", "activestorage",
        "activesupport", "addressable", "administrate", "airbrussh",
        "arbre", "ast", "audited", "aws-eventstream", "aws-partitions",
        "aws-sdk-core", "aws-sdk-kms", "aws-sdk-s3", "aws-sigv4", "base64",
        "bcrypt", "better_html", "bigdecimal", "bindex", "bootsnap",
        "brakeman", "builder", "bullet", "bundler", "byebug", "cancancan",
        "capistrano", "capistrano-bundler", "capistrano-rails", "capybara",
        "carrierwave", "coderay", "concurrent-ruby", "connection_pool",
        "content_disposition", "crack", "crass", "csv",
        "database_cleaner-active_record", "database_cleaner-core", "debug",
        "devise", "diff-lcs", "docile", "domain_name", "doorkeeper",
        "dotenv", "down", "dry-configurable", "dry-core", "dry-inflector",
        "dry-initializer", "dry-logger", "dry-logic", "dry-monads",
        "dry-monitor", "dry-schema", "dry-struct", "dry-system",
        "dry-types", "dry-validation", "erb_lint", "erubi", "excon",
        "factory_bot", "factory_bot_rails", "faker", "faraday",
        "faraday-net_http", "ffi", "formtastic", "formtastic_i18n", "fugit",
        "globalid", "googleauth", "grape", "hanami", "hanami-cli",
        "hanami-utils", "hashdiff", "hashie", "http-accept", "http-cookie",
        "httparty", "httpclient", "i18n", "ice_nine", "image_processing",
        "inherited_resources", "irb", "jbuilder", "jmespath",
        "jquery-rails", "json", "jwt", "kaminari", "kaminari-actionview",
        "kaminari-activerecord", "kaminari-core",
        "language_server-protocol", "lint_roller", "logger", "loofah",
        "mail", "marcel", "matrix", "method_source", "mime-types",
        "mime-types-data", "mini_mime", "mini_portile2", "minitest",
        "mongo", "mongoid", "msgpack", "multi_json", "multi_xml",
        "multipart-post", "mustermann", "netrc", "nio4r", "nokogiri",
        "oauth2", "omniauth", "omniauth-oauth2", "orm_adapter", "ostruct",
        "pagy", "paper_trail", "parallel", "parser", "pg", "pry",
        "pry-rails", "public_suffix", "puma", "pundit", "racc", "rack",
        "rack-attack", "rack-cors", "rack-protection", "rack-proxy",
        "rack-session", "rack-test", "rails", "rails-dom-testing",
        "rails-html-sanitizer", "railties", "rainbow", "rake", "ransack",
        "rb-fsevent", "redis", "redis-client", "regexp_parser", "reline",
        "request_store", "responders", "rest-client", "rexml", "rom",
        "rom-changeset", "rom-core", "rom-repository", "rspec",
        "rspec-core", "rspec-expectations", "rspec-mocks", "rspec-rails",
        "rspec-support", "rubocop", "rubocop-ast", "rubocop-performance",
        "rubocop-rails", "ruby-progressbar", "rubygems-update", "rubyzip",
        "sassc", "sassc-rails", "semantic_range", "sentry-rails",
        "sentry-ruby", "sequel", "shoulda-matchers", "shrine", "sidekiq",
        "signet", "simplecov", "smart_properties", "solid_cable",
        "solid_cache", "solid_queue", "sprockets", "sprockets-rails",
        "sshkit", "ssrf_filter", "state_machines-activemodel",
        "state_machines-activerecord", "stimulus-rails",
        "tailwindcss-rails", "tailwindcss-ruby", "thor", "thread_safe",
        "tilt", "turbo-rails", "tzinfo", "unf", "unf_ext",
        "unicode-display_width", "uniform_notifier", "uri", "vcr",
        "view_component", "warden", "web-console", "webmock", "webpacker",
        "websocket-driver", "websocket-extensions", "will_paginate",
        "xpath", "yaml", "zeitwerk",
    }

    _PHP_PACKAGES = {
        "guzzlehttp/guzzle", "symfony/console", "symfony/framework-bundle",
        "symfony/http-foundation", "symfony/http-kernel", "symfony/routing",
        "symfony/dependency-injection", "symfony/config", "symfony/yaml",
        "symfony/finder", "symfony/process", "symfony/event-dispatcher",
        "symfony/var-dumper", "symfony/error-handler", "symfony/serializer",
        "symfony/property-access", "symfony/security-core",
        "doctrine/orm", "doctrine/dbal", "doctrine/common",
        "laravel/framework", "illuminate/support", "illuminate/database",
        "illuminate/routing", "illuminate/container",
        "phpunit/phpunit", "mockery/mockery", "monolog/monolog",
        "vlucas/phpdotenv", "nesbot/carbon", "league/flysystem",
        "phpoffice/phpspreadsheet", "twig/twig", "slim/slim",
        "squizlabs/php_codesniffer", "phpstan/phpstan", "composer/composer",
        "phpspec/prophecy", "guzzlehttp/promises", "guzzlehttp/psr7",
        "psr/log", "psr/http-message", "psr/container", "psr/cache",
        "psr/simple-cache", "psr/event-dispatcher", "psr/http-factory",
        "psr/http-server-handler", "psr/http-server-middleware",
        "brick/math", "dragonmantank/cron-expression",
        "dompdf/dompdf", "phpmailer/phpmailer",
        "stripe/stripe-php", "firebase/php-jwt",
        "aws/aws-sdk-php", "google/auth", "google/apiclient",
        "ramsey/uuid", "fideloper/proxy", "phpseclib/phpseclib",
        "briannesbitt/carbon", "league/oauth2-server",
        "php-http/guzzle7-adapter", "php-http/httplug",
        "guzzlehttp/guzzle-services", "fzaninotto/faker",
        "psy/psysh", "dnoegel/php-xdg-base-dir",
        "nikic/php-parser", "sebastian/comparator",
        "sebastian/diff", "sebastian/environment",
        "sebastian/exporter", "sebastian/global-state",
        "sebastian/object-enumerator", "sebastian/recursion-context",
        "sebastian/resource-operations", "sebastian/type",
        "theseer/tokenizer", "webmozart/assert",
        "filp/whoops", "fzaninotto/faker",
    }

    _SWIFT_PACKAGES = {
        "github.com/alamofire/alamofire",
        "github.com/apple/swift-algorithms",
        "github.com/apple/swift-argument-parser",
        "github.com/apple/swift-async-algorithms",
        "github.com/apple/swift-collections",
        "github.com/apple/swift-crypto",
        "github.com/apple/swift-docc-plugin",
        "github.com/apple/swift-log",
        "github.com/apple/swift-nio",
        "github.com/apple/swift-numerics",
        "github.com/apple/swift-protobuf",
        "github.com/apple/swift-syntax",
        "github.com/apple/swift-system",
        "github.com/firebase/firebase-ios-sdk",
        "github.com/getsentry/sentry-cocoa",
        "github.com/onevcat/kingfisher",
        "github.com/realm/realm-swift",
        "github.com/siteline/swiftui-introspect",
        "github.com/snapkit/snapkit",
        "github.com/swiftyjson/swiftyjson",
    }

    _ELIXIR_PACKAGES = {
        "absinthe", "bandit", "broadway", "castore", "comeonin", "decimal",
        "ecto", "ecto_sql", "esbuild", "ex_doc", "finch", "floki", "gettext",
        "hackney", "jason", "jose", "mime", "mint", "nimble_options", "oban",
        "phoenix", "phoenix_ecto", "phoenix_html", "phoenix_live_view",
        "phoenix_pubsub", "plug", "plug_cowboy", "postgrex", "req", "swoosh",
        "telemetry", "tesla", "websock", "websock_adapter",
    }

    _DART_PACKAGES = {
        "async", "collection", "cupertino_icons", "dio", "flutter_lints",
        "go_router", "http", "intl", "json_annotation", "meta", "path",
        "provider", "riverpod", "shared_preferences", "sqflite", "test",
        "url_launcher", "uuid", "yaml",
    }
