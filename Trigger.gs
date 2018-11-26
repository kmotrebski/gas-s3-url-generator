
// This is exemplary function that you can use to automatically update
// data in your spreadsheet. You need to set up scheduled "trigger" in
// script settings.

// While being inside the Script Editor go to:
// "Edit" > "Current project's triggers" -> "Add Triggers"

function trigger1() {
    var fileUrl = getS3SignedGetUrl('bucket_name', 'path/to/file.csv');
    var formula = '=IMPORTDATA("' + fileUrl + '")';

    SpreadsheetApp.getActiveSheet().getRange('E1').setFormula(formula);
}
