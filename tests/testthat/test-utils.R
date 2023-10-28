without_internet({
  test_that("Can query PyPI...", {
    query_1 <- RosvQuery1$new()
    expect_POST(query_1$run(name = 'dask', ecosystem = 'PyPI'),
                'https://api.osv.dev/v1/query',
                '{"commit":null,"version":null,"package":{"name":"dask","ecosystem":"PyPI","purl":null},"page_token":null}')
  })
})
