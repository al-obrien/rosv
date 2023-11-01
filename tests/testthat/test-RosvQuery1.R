without_internet({
  test_that("Can create a well-formed RosvQuery1 object...", {
    query_1 <- RosvQuery1$new(name = 'dask', ecosystem = 'PyPI')
    expect_POST(query_1$run(),
                'https://api.osv.dev/v1/query',
                '{"commit":null,"version":null,"package":{"name":"dask","ecosystem":"PyPI","purl":null},"page_token":null}')
  })
})

without_internet({
  test_that("Check error checking on RosvQuery1 objects...", {
    # Only length 1 allowed
    expect_error(RosvQuery1$new(name = c('pandas', 'dask'), ecosystem = c('PyPI', 'PyPI')),
                 'Only one package and version can be provided')

    # Must give valid ecosystem
    expect_error(RosvQuery1$new(name = c('pandas'), ecosystem = c('PyI')))

    # Combination errors checked
    expect_error(RosvQuery1$new(name = c('pandas')),
                 'If using package name, ecosystem must also be set')
    expect_error(RosvQuery1$new(commit = 'somerandomhash', version = '1.0.0'),
                 'Cannot provide commit hash and version at the same time')
    expect_error(RosvQuery1$new(commit = 'somerandomhash', name = 'pandas', ecosystem = 'PyPI'),
                 'Separate commit hash queries from package based queries')
    expect_error(RosvQuery1$new(purl = 'somepackageurl', name = 'pandas'),
                 'Cannot provide purl with name or ecosystem also set.')
    expect_error(RosvQuery1$new(name = c('pandas'), version = c('1.1', '1.2')))
  })
})
