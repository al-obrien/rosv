test_that('PyPI package names can be normalized...', {
  expect_equal(normalize_pypi_pkg(c('Dask', 'TenSorFlow')), c('dask', 'tensorflow'))
})

test_that('Correct ecosystems can be checked...', {
  skip_on_cran()
  expect_equal(check_ecosystem(c('PyPI', 'CRAN')), c('PyPI', 'CRAN'))
  expect_error(check_ecosystem(c('pypi')))
})

test_that('Ensure rosv type check is selective...', {
  expect_true(is_rosv(RosvQuery1$new(name = 'pandas', ecosystem = 'PyPI')))
  expect_true(is_rosv(RosvQueryBatch$new(name = 'pandas', ecosystem = 'PyPI')))
  expect_true(is_rosv(RosvVulns$new('RSEC-2023-6')))

  expect_true(validate_rosv(RosvQuery1$new(name = 'pandas', ecosystem = 'PyPI')))
  expect_true(validate_rosv(RosvQueryBatch$new(name = 'pandas', ecosystem = 'PyPI')))
  expect_true(validate_rosv(RosvVulns$new('RSEC-2023-6')))

  expect_false(is_rosv(c(1,2,3)))
  expect_false(is_rosv(data.frame(test = c(1,2,3))))

  expect_error(validate_rosv(c(1,2,3)))
  expect_error(validate_rosv(data.frame(test = c(1,2,3))))
})

test_that('Ensure API affected package filtering operates...', {
  example_data <- data.frame(id = c(rep('PYSEC-2021-387', 3), 'PYSEC-2020-73'),
                             name = c(rep('dask', 3), 'pandas'),
                             ecosystem = rep('PyPI', 4),
                             versions = c('0.10.0', '0.10.1', '0.11.0', '0.25.3'))

  expect_equal(nrow(filter_affected(example_data, name = 'dask', ecosystem = 'PyPI', version = NA)), 3)
  expect_equal(nrow(filter_affected(example_data, name = 'dask', ecosystem = 'PyPI', version = '0.11.0')), 1)
  expect_error(filter_affected(example_data, name = c('dask', 'dask'), ecosystem = c('PyPI', 'PyPI'), version = c(NA, '0.10.0')))
  expect_equal(nrow(filter_affected(example_data, name = c('dask', 'pandas'), ecosystem = c('PyPI', 'PyPI'), version = c('0.11.0', NA))), 2)
  expect_equal(nrow(filter_affected(example_data, name = c('dask', 'pandas'), ecosystem = c('PyPI', 'PyPI'), version = c('0.11.0', '1.1.1'))), 1)

  # Test ordering of columns in maintained
  expect_equal(colnames(filter_affected(example_data, name = 'dask', ecosystem = 'PyPI', version = NA)), colnames(example_data))
})

test_that('Can retrieve R6 class contents before running query...', {
  newobj <- RosvQuery1$new(name = 'readxl', ecosystem = 'CRAN')
  expect_null(get_rosv(newobj, 'content'))
})
