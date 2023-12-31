unit WebModuleUnit1;

interface

uses System.SysUtils, System.Classes, Web.HTTPApp, FireDAC.Stan.Intf,
  FireDAC.Stan.Option, FireDAC.Stan.Error, FireDAC.UI.Intf, FireDAC.Phys.Intf,
  FireDAC.Stan.Def, FireDAC.Stan.Pool, FireDAC.Stan.Async, FireDAC.Phys,
  FireDAC.Phys.MySQL, FireDAC.Phys.MySQLDef, FireDAC.Stan.Param, FireDAC.DatS,
  FireDAC.DApt.Intf, FireDAC.DApt, Data.DB, FireDAC.Comp.DataSet,
  FireDAC.Comp.Client, Web.HTTPProd,
  Web.DBWeb, FireDAC.Stan.ExprFuncs, IniFiles, FireDAC.Phys.IB,
  FireDAC.Phys.IBDef, System.AnsiStrings, System.NetEncoding, System.Variants,
  FireDAC.VCLUI.Wait,
  Web.DSProd, FireDAC.Phys.PG, FireDAC.Phys.PGDef, FireDAC.Phys.SQLite,
  FireDAC.Phys.SQLiteDef, FireDAC.Phys.SQLiteWrapper.Stat,
  FireDAC.Phys.IBLiteDef, FireDAC.Phys.FB, FireDAC.Phys.FBDef, IdBaseComponent,
  IdComponent, IdTCPConnection, IdTCPClient, IdHTTP, REST.Types,
  REST.Response.Adapter, REST.Client, Data.Bind.Components,
  Data.Bind.ObjectScope;

type
  TFindState = (fdShort, fdNormal, fdNone);

  TPageSearch = class
  private
    FText: string;
    FWordList, FList, FResultLST: TStringList;
    function checkState(var st: integer; word, line: string): TFindState;
    procedure processNormal(var id: integer; word, line: string);
    procedure processShort(var id, ln: integer; word: string; var line: string);
  public
    constructor Create;
    destructor Destroy; override;
    function Execute(const Text: string): string; virtual;
    property WordList: TStringList read FWordList;
  end;

  TWebModule1 = class(TWebModule)
    FDConnection1: TFDConnection;
    FDTable1: TFDTable;
    FDTable2: TFDTable;
    DataSetPageProducer1: TDataSetPageProducer;
    PageProducer1: TPageProducer;
    DataSetPageProducer2: TDataSetPageProducer;
    DataSetTableProducer1: TDataSetTableProducer;
    PageProducer2: TPageProducer;
    DataSetPageProducer3: TDataSetPageProducer;
    PageProducer3: TPageProducer;
    PageProducer4: TPageProducer;
    PageProducer5: TPageProducer;
    DataSetPageProducer4: TDataSetPageProducer;
    WebFileDispatcher1: TWebFileDispatcher;
    PageProducer7: TPageProducer;
    DataSource1: TDataSource;
    FDQuery1: TFDQuery;
    FDQuery2: TFDQuery;
    PageProducer6: TPageProducer;
    RESTClient1: TRESTClient;
    RESTRequest1: TRESTRequest;
    RESTResponse1: TRESTResponse;
    RESTResponseDataSetAdapter1: TRESTResponseDataSetAdapter;
    DataSetTableProducer2: TDataSetTableProducer;
    PageProducer8: TPageProducer;
    FDMemTable1: TFDMemTable;
    FDMemTable1id: TFloatField;
    FDMemTable1rank: TFloatField;
    FDMemTable1adtext: TWideStringField;
    FDMemTable1company: TWideStringField;
    FDMemTable1active: TBooleanField;
    FDTable2DBNUMBER: TIntegerField;
    FDTable2CMNUMBER: TIntegerField;
    FDTable2TITLENUM: TIntegerField;
    FDTable2COMMENT: TWideMemoField;
    FDTable2DATETIME: TDateField;
    FDTable1ID: TIntegerField;
    FDTable1DBNUMBER: TIntegerField;
    FDTable1TITLENUM: TIntegerField;
    PageProducer10: TPageProducer;
    DataSetPageProducer5: TDataSetPageProducer;
    FDTable2comcnt: TIntegerField;
    FDTable1DBNAME: TWideStringField;
    FDTable1TITLE: TWideStringField;
    PageProducer9: TPageProducer;
    procedure DataSetPageProducer1HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure DataSetTableProducer1FormatCell(Sender: TObject;
      CellRow, CellColumn: integer; var BgColor: THTMLBgColor;
      var Align: THTMLAlign; var VAlign: THTMLVAlign;
      var CustomAttrs, CellData: string);
    procedure WebModuleCreate(Sender: TObject);
    procedure PageProducer2HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure WebModule1WebActionItem2Action(Sender: TObject;
      Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
    procedure DataSetPageProducer3HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure PageProducer3HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure WebModuleBeforeDispatch(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure WebModule1WebActionItem6Action(Sender: TObject;
      Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
    procedure WebModule1WebActionItem7Action(Sender: TObject;
      Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
    procedure DataSetPageProducer2HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure WebModuleDestroy(Sender: TObject);
    procedure PageProducer5HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure WebModule1searchItemAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure WebModule1mainItemAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure PageProducer7HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure PageProducer1HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure WebModule1adminPageAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure WebModule1showTopAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure WebModule1masterAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure PageProducer6HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure DataSetTableProducer2CreateContent(Sender: TObject;
      var Continue: Boolean);
    procedure PageProducer8HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure WebModule1membersAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure PageProducer10HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
    procedure PageProducer9HTMLTag(Sender: TObject; Tag: TTag;
      const TagString: string; TagParams: TStrings; var ReplaceText: string);
  private
    { private 宣言 }
    count: integer;
    pagecount: integer;
    idcount: integer;
    link: integer;
    mente: Boolean;
    isget: Boolean;
    commentoff: Boolean;
    adtext: string;
    mysearch: TPageSearch;
    bglist: TStringList;
    function readComment(const Text: string; st, cnt: integer): string;
    function makeComment(const Text: string; cnt: integer): string;
    function makeFooter(script: string): string;
    function ActiveRecordisNew: Boolean;
    function replaceRawData(Data: string): string;
    procedure islastproc;
  public
    { public 宣言 }
  end;

var
  WebModuleClass: TComponentClass = TWebModule1;

implementation

{ %CLASSGROUP 'Vcl.Controls.TControl' }

{$R *.dfm}

const
  fname = 'data/voice.txt';

function TWebModule1.ActiveRecordisNew: Boolean;
var
  day: TDateTime;
begin
  FDQuery2.SQL.Text :=
    'select max(datetime) as large from maintable where dbnumber = :db;';
  FDQuery2.ParamByName('db').AsInteger := FDQuery1.FieldByName('dbnumber')
    .AsInteger;
  FDQuery2.Open;
  day := Now - FDQuery2.FieldByName('large').AsDateTime;
  FDQuery2.Close;
  result := day < 1;
end;

procedure TWebModule1.islastproc;
var
  i: integer;
begin
  i := StrToIntDef(Request.QueryFields.Values['page'], 0);
  if (i = 0) or ((i - 1) * count >= FDTable2.RecordCount) then
  begin
    idcount := 0;
    FDTable2.Last;
    FDTable2.MoveBy(-count + 1);
  end
  else
  begin
    idcount := i;
    FDTable2.First;
    FDTable2.MoveBy((idcount - 1) * count);
  end;
end;

procedure TWebModule1.DataSetPageProducer1HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
var
  cnt, com: integer;
  s: string;
begin
  islastproc;
  if TagString = 'form' then
  begin
    if count * pagecount > FDTable2.RecordCount then
      ReplaceText := DataSetPageProducer4.Content
    else
      ReplaceText := '<h1>書き込み最大数に達しました。これ以上書き込めません。</h1>';
  end
  else if TagString = 'main' then
  begin
    cnt := count;
    com := 3;
    s := FDTable1.FieldByName('dbname').AsString;
    while not FDTable2.Eof and (cnt > 0) do
    begin
      if com = 0 then
      begin
        ReplaceText := ReplaceText +
          Format('<hr><p>広告</p><div align="center">%s</div><hr>',
          [FDMemTable1.FieldByName('adtext').AsString]);
        FDMemTable1.Next;
        if FDMemTable1.Eof then
          FDMemTable1.First;
        com := 5;
      end;
      ReplaceText := ReplaceText + DataSetPageProducer2.Content +
        Format('<p style="text-align:end"><a href="/alert?db=%s&tn=%d&page=%d">報告</a></p>',
        [s, FDTable1.FieldByName('titlenum').AsInteger,
        FDTable2.FieldByName('cmnumber').AsInteger]);
      FDTable2.Next;
      dec(cnt);
      dec(com);
    end;
  end
  else if TagString = 'footer' then
    ReplaceText := makeFooter('bbs');
end;

procedure TWebModule1.DataSetPageProducer2HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
var
  Text: string;
  cnt: integer;
  DataSet: TDataSet;
begin
  if TagString = 'comment' then
  begin
    if commentoff then
      ReplaceText := ''
    else
    begin
      DataSet := DataSetPageProducer2.DataSet;
      cnt := DataSet.FieldByName('comcnt').AsInteger;
      Text := DataSet.FieldByName('comment').AsString;
      ReplaceText := makeComment(Text, cnt);
    end;
  end;
end;

procedure TWebModule1.DataSetPageProducer3HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
begin
  if TagString = 'article' then
  begin
    if isget then
      ReplaceText := DataSetPageProducer2.Content;
  end
  else if TagString = 'message' then
  begin
    if isget then
      ReplaceText :=
        '<textarea name=com></textarea><p style=text-align:center><input name=admit type=submit value="送信">'
    else
      ReplaceText := 'ご協力ありがとうございました';
  end
  else if TagString = 'query' then
    ReplaceText := Request.Query;
end;

procedure TWebModule1.DataSetTableProducer1FormatCell(Sender: TObject;
  CellRow, CellColumn: integer; var BgColor: THTMLBgColor;
  var Align: THTMLAlign; var VAlign: THTMLVAlign;
  var CustomAttrs, CellData: string);
var
  s: string;
begin
  if CellRow > 0 then
    case CellColumn of
      0:
        CellData := Format('<input type=checkbox name=check value=%d>',
          [FDTable2.FieldByName('cmnumber').AsInteger]);
      4:
        begin
          s := Request.QueryFields.Values['page'];
          if s <> '' then
            s := '&page=' + s;
          CellData := Format('<a href="/admin?db=%s&tn=%s%s&link=%d">go</a>',
            [Request.QueryFields.Values['db'], Request.QueryFields.Values['tn'],
            s, FDTable2.FieldByName('cmnumber').AsInteger]);
        end;
    end;
  if (CellRow > 1) and (CellRow mod 2 = 0) then
    BgColor := 'Silver';
end;

procedure TWebModule1.DataSetTableProducer2CreateContent(Sender: TObject;
  var Continue: Boolean);
begin
  DataSetTableProducer2.Header.Text := PageProducer8.Content;
end;

function TWebModule1.makeComment(const Text: string; cnt: integer): string;
var
  s, t: string;
  ls: TStringList;
begin
  ls := TStringList.Create;
  try
    ls.Text := Text;
    if cnt = -1 then
      cnt := ls.count;
    for var i := 0 to cnt - 1 do
    begin
      s := ls[i];
      t := '';
      if s = '' then
        s := '<br>'
      else
        for var j := 1 to Length(s) do
          if s[j] = ' ' then
            t := t + '&nbsp;'
          else
          begin
            s := t + Copy(s, j - 1, Length(s));
            break;
          end;
      ls[i] := '<p>' + s + '</p>';
    end;
    if cnt < ls.count then
    begin
      ls.Insert(cnt, '<pre><code>');
      ls.Add('</code></pre>');
    end;
    result := ls.Text;
  finally
    ls.Free;
  end;
end;

function TWebModule1.makeFooter(script: string): string;
var
  s, t, tn: string;
begin
  if idcount = 0 then
    t := 'active'
  else
    t := '';
  bglist.Clear;
  bglist.Add
    ('<nav aria-label="Page navigation"><ul class="pagination pagination-sm justify-content-center">');
  s := Request.QueryFields.Values['db'];
  tn := Request.QueryFields.Values['tn'];
  for var i := 1 to pagecount do
  begin
    if i = idcount then
      bglist.Add('<li class="page-item active">')
    else
      bglist.Add('<li class="page-item">');
    bglist.Add
      (Format('<a class="page-link" href="/%s?db=%s&tn=%s&page=%d">%d</a></li>',
      [script, s, tn, i, i]));
  end;
  bglist.Add
    (Format('<li class="page-item %s"><a class="page-link" href="/%s?db=%s&tn=%s">さいご</a></li></ul></nav>',
    [t, script, s, tn]));
  result := bglist.Text;
end;

procedure TWebModule1.PageProducer10HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
var
  str1, str2: string;
  num: integer;
begin
  if (TagString = 'form') and (Request.PathInfo = '/members') then
    ReplaceText := DataSetPageProducer5.Content;
  if TagString = 'table' then
  begin
    str1 := FDTable1.FieldByName('dbname').AsString;
    while not FDTable1.Eof do
    begin
      if FDTable2.Eof then
      begin
        FDTable1.Next;
        Continue;
      end;
      str2 := FDTable1.FieldByName('title').AsString;
      num := FDTable1.FieldByName('titlenum').AsInteger;
      ReplaceText := ReplaceText +
        Format('<p align="center"><a href="/bbs?db=%s&tn=%d">%s</a></p>',
        [str1, num, str2]);
      FDTable1.Next;
    end;
  end;
  if TagString = 'dbname' then
    ReplaceText := FDTable1.FieldByName('dbname').AsString;
  if (TagString = 'title') and (Request.PathInfo = '/list') then
    ReplaceText := Format('<div align="center">%s</div>',
      [FDTable1.FieldByName('title').AsString]);
end;

procedure TWebModule1.PageProducer1HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
begin
  if TagString = 'main' then
    ReplaceText := PageProducer7.Content;
end;

procedure TWebModule1.PageProducer2HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
begin
  islastproc;
  if TagString = 'table' then
    ReplaceText := DataSetTableProducer1.Content
  else if TagString = 'dbname' then
    ReplaceText := Request.QueryFields.Values['db']
  else if TagString = 'titlenum' then
    ReplaceText := Request.QueryFields.Values['tn']
  else if TagString = 'footer' then
    ReplaceText := makeFooter('admin')
  else if (TagString = 'section') and FDTable2.Locate('cmnumber', link) then
    ReplaceText := DataSetPageProducer2.Content;
end;

procedure TWebModule1.PageProducer3HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
var
  temp, Text, bbsName: string;
  cnt: integer;
begin
  if TagString = 'adtext' then
    ReplaceText := adtext
  else if (TagString = 'main') and (Request.MethodType = mtPost) then
  begin
    if Request.ContentFields.Values['filter'] = 'com' then
      commentoff := true;
    FDQuery1.Open('select * from maintable order by datetime desc;');
    FDQuery2.Open('select * from nametable;');
    DataSetPageProducer2.DataSet := FDQuery1;
    try
      while not FDQuery1.Eof do
      begin
        if not FDQuery2.Locate('dbnumber;titlenum',
          VarArrayOf([FDQuery1.FieldByName('dbnumber').AsVariant,
          FDQuery1.FieldByName('titlenum').AsVariant])) then
        begin
          FDQuery1.Next;
          Continue;
        end;
        bbsName := Format('(%s:%s)', [FDQuery2.FieldByName('dbname').AsString,
          FDQuery2.FieldByName('title').AsString]);
        cnt := FDQuery1.FieldByName('comcnt').AsInteger;
        temp := readComment(FDQuery1.FieldByName('comment').AsString, 0, cnt);
        Text := mysearch.Execute(temp);
        if Text <> '' then
        begin
          temp := '<pre><code>' + readComment(FDQuery1.FieldByName('comment')
            .AsString, cnt, -1) + '</code></pre>';
          ReplaceText := ReplaceText + bbsName + DataSetPageProducer2.Content +
            makeComment(Text, -1) + temp + '<hr>';
        end;
        FDQuery1.Next;
      end;
    finally
      DataSetPageProducer2.DataSet := FDTable2;
      FDQuery1.Close;
      FDQuery2.Close;
      commentoff := false;
    end;
    if ReplaceText = '' then
      ReplaceText := '見つかりませんでした';
    ReplaceText := '<hr>' + ReplaceText;
  end
  else if TagString = 'word' then
    ReplaceText := mysearch.WordList.DelimitedText;
end;

procedure TWebModule1.PageProducer5HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
begin
  if isget then
    ReplaceText := '<p><input type=submit value="送信"></p>';
end;

procedure TWebModule1.PageProducer6HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
begin
  if TagString = 'link' then
    ReplaceText := '';
end;

procedure TWebModule1.PageProducer7HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
const
  conf = 7;
var
  s, t: string;
begin
  FDQuery1.Open('select * from nametable where titlenum = 1;');
  if TagString = 'first' then
  begin
    for var i := 0 to (FDQuery1.RecordCount - 1) div conf do
      if i = 0 then
        ReplaceText :=
          '<li data-target="#slide-1" data-slide-to="0" class="active"></li>'
      else
        ReplaceText := ReplaceText +
          Format('<li data-target="#slide-1" data-slide-to=%d></li>', [i]);
  end
  else if TagString = 'second' then
  begin
    bglist.Clear;
    for var i := 0 to (FDQuery1.RecordCount - 1) div conf do
    begin
      if i = 0 then
        bglist.Add('<div class="carousel-item active">')
      else
        bglist.Add('<div class="carousel-item">');
      bglist.Add
        (Format('<img class="d-sm-block d-none" src="img/slide%d.jpg" style="float:right;height:465px">',
        [i + 1]));
      bglist.Add('<div style="height:465px"></div>');
      bglist.Add
        ('<div class="carousel-caption text-left" style="font-size:1.5rem;">');
      for var j := 1 to conf do
      begin
        if FDQuery1.Eof then
          break;
        t := FDQuery1.FieldByName('dbname').AsString;
        if ActiveRecordisNew then
          s := ' style="background-color:aqua;"'
        else
          s := '';
        FDQuery1.Next;
        bglist.Add(Format('<p><a href="/list?db=%s"%s target=_blank>%s</a></p>',
          [t, s, t]));
      end;
      bglist.Add('</div></div>');
    end;
    ReplaceText := bglist.Text;
    FDQuery1.Close;
  end;
end;

procedure TWebModule1.PageProducer8HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
begin
  if (TagString = 'checked') and mente then
    ReplaceText := 'checked';
end;

procedure TWebModule1.PageProducer9HTMLTag(Sender: TObject; Tag: TTag;
  const TagString: string; TagParams: TStrings; var ReplaceText: string);
var
  ls: TStringList;
begin
  ls:=TStringList.Create;
  try
    ls.LoadFromFile('.\js\login.js');
    ReplaceText:=ls.Text;
  finally
    ls.Free;
  end;
end;

function TWebModule1.readComment(const Text: string; st, cnt: integer): string;
var
  ls1, ls2: TStringList;
  num: integer;
begin
  if (st = -1) or (Text = '') then
    Exit('');
  ls1 := TStringList.Create;
  ls2 := TStringList.Create;
  try
    ls1.Text := Text;
    if cnt = -1 then
      num := ls1.count - 1
    else
      num := st + cnt - 1;
    for var i := st to num do
      ls2.Add(ls1[i]);
    result := ls2.Text;
  finally
    ls1.Free;
    ls2.Free;
  end;
end;

function TWebModule1.replaceRawData(Data: string): string;
const
  ng = '死ね,阿保,馬鹿,殺す,爆破';
var
  list: TStringList;
  s: string;
begin
  result := Data;
  list := TStringList.Create;
  try
    list.DelimitedText := ng;
    for s in list do
      result := String(ReplaceText(AnsiString(result), AnsiString(s),
        AnsiString('*****')));
  finally
    list.Free;
  end;
end;

procedure TWebModule1.WebModule1adminPageAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
begin
  if not FDTable1.Locate('dbname;titlenum',
    VarArrayOf([Request.QueryFields.Values['db'],
    Request.QueryFields.Values['tn']])) then
  begin
    Handled := false;
    Exit;
  end;
  if Request.MethodType = mtPost then
    for var i := 0 to Request.ContentFields.count - 1 do
      if Request.ContentFields.Names[i] = 'check' then
      begin
        FDTable2.First;
        while FDTable2.Locate('cmnumber',
          Request.ContentFields.ValueFromIndex[i]) do
          FDTable2.Delete;
        if FDTable2.RecordCount = 0 then
          FDTable1.Delete;
      end;
  link := StrToIntDef(Request.QueryFields.Values['link'], 0);
  Response.ContentType := 'text/html;charset=utf-8;';
  Response.Content := PageProducer2.Content;
end;

procedure TWebModule1.WebModule1mainItemAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var
  DB, raw: string;
  i, j, tid, cnt: integer;
begin
  tid := StrToIntDef(Request.QueryFields.Values['tn'], 0);
  DB := Request.QueryFields.Values['db'];
  if not FDTable1.Locate('dbname;titlenum', VarArrayOf([DB, tid])) then
  begin
    Handled := false;
    Exit;
  end;
  if Request.MethodType = mtPost then
  begin
    raw := replaceRawData(Request.ContentFields.Values['comment']);
    FDTable2.Last;
    i := FDTable1.FieldByName('dbnumber').AsInteger;
    j := FDTable2.FieldByName('cmnumber').AsInteger + 1;
    bglist.Text := TNetEncoding.HTML.Encode(raw);
    raw := Request.ContentFields.Values['code'];
    cnt := -1;
    if raw <> '' then
    begin
      cnt := bglist.count;
      bglist.Add(raw);
    end;
    FDTable2.AppendRecord([i, j, tid, bglist.Text, Now, cnt]);
  end;
  Response.ContentType := 'text/html;charset=utf-8';
  Response.Content := DataSetPageProducer1.Content;
end;

procedure TWebModule1.WebModule1masterAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var
  cnt, id: integer;
  s: string;
begin
  if Request.MethodType = mtPost then
  begin
    mente := Request.ContentFields.Values['switch'] = 'mente';
    bglist.Text := Request.ContentFields.Values['subjects'];
    FDQuery1.Open('select max(dbnumber) as large from nametable;');
    cnt := FDQuery1.FieldByName('large').AsInteger + 1;
    FDQuery1.Open('select max(id) as large from nametable;');
    id := FDQuery1.FieldByName('large').AsInteger + 1;
    FDQuery1.Close;
    for var i := 0 to bglist.count - 1 do
    begin
      s := bglist[i];
      if (s <> '') and not FDTable1.Locate('dbname', s) then
      begin
        FDTable1.AppendRecord([id, cnt, s, 1, 'New Space!!']);
        inc(id);
        inc(cnt);
      end;
    end;
  end;
  RESTRequest1.Execute;
  FDMemTable1.First;
  Response.ContentType := 'text/html;charset=utf8';
  Response.Content := DataSetTableProducer2.Content;
end;

procedure TWebModule1.WebModule1membersAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var
  DB, title, code: string;
  i, j, k, cnt: integer;
begin
  DB := Request.QueryFields.Values['db'];
  FDTable1.Filter := 'dbname = ' + QuotedStr(DB);
  FDTable1.Filtered := true;
  if FDTable1.RecordCount = 0 then
    Response.SendRedirect('/top');
  if Request.MethodType = mtPost then
  begin
    title := Request.ContentFields.Values['title'];
    bglist.Text := Request.ContentFields.Values['comment'];
    code := Request.ContentFields.Values['code'];
    cnt := -1;
    if code <> '' then
    begin
      cnt := bglist.count;
      bglist.Add(Format('<pre><code>%s</code></pre>', [code]));
    end;
    FDTable1.Last;
    FDQuery1.Open('select max(id) as large from nametable;');
    i := FDTable1.FieldByName('dbnumber').AsInteger;
    j := FDTable1.FieldByName('titlenum').AsInteger + 1;
    k := FDQuery1.FieldByName('large').AsInteger + 1;
    FDQuery1.Close;
    FDTable1.AppendRecord([k, i, DB, j, title]);
    FDTable2.AppendRecord([i, 1, j, bglist.Text, Now, cnt]);
  end;
  FDTable1.First;
  Response.ContentType := 'text/html;charset=utf8';
  Response.Content := PageProducer10.Content;
end;

procedure TWebModule1.WebModule1searchItemAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
begin
  mysearch := TPageSearch.Create;
  try
    mysearch.WordList.DelimitedText := Request.ContentFields.Values['word1'];
    Response.ContentType := 'text/html;charset=utf8';
    Response.Content := PageProducer3.Content;
  finally
    mysearch.Free;
  end;
end;

procedure TWebModule1.WebModule1showTopAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var
  s: string;
begin
  s := Request.QueryFields.Values['db'];
  if (Request.MethodType = mtPost) and FDTable1.Locate('dbname;titlenum',
    VarArrayOf([s, Request.QueryFields.Values['tn']])) then
  begin
    FDTable2.First;
    while not FDTable2.Eof do
      FDTable2.Delete;
    FDTable1.Delete;
  end;
  Response.ContentType := 'text/html;charset=utf-8';
  Response.Content := PageProducer1.Content;
end;

procedure TWebModule1.WebModule1WebActionItem2Action(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var
  fs: TFileStream;
begin
  if not(FDTable1.Locate('dbname;titlenum',
    VarArrayOf([Request.QueryFields.Values['db'],
    Request.QueryFields.Values['tn']])) and FDTable2.Locate('cmnumber',
    Request.QueryFields.Values['page'])) then
  begin
    Handled := false;
    Exit;
  end;
  if Request.MethodType = mtGet then
    isget := true
  else if Request.MethodType = mtPost then
  begin
    isget := false;
    fs := TFileStream.Create(fname, fmCreate);
    try
      bglist.Clear;
      bglist.Add('');
      bglist.Add('(*ユーザー様から報告がありました*)');
      bglist.Add(DateToStr(Now));
      bglist.Add(FDTable1.FieldByName('dbname').AsString);
      bglist.Add(FDTable2.FieldByName('cmnumber').AsString);
      bglist.Add(FDTable1.FieldByName('title').AsString);
      bglist.Add(FDTable2.FieldByName('datetime').AsString);
      bglist.Add(FDTable2.FieldByName('comment').AsString);
      bglist.Add(Request.ContentFields.Values['com']);
      bglist.Add('(*報告ここまで*)');
      bglist.Add('');
      bglist.SaveToStream(fs);
    finally
      fs.Free;
    end;
  end;
  Response.ContentType := 'text/html;charset=utf-8';
  Response.Content := DataSetPageProducer3.Content;
end;

procedure TWebModule1.WebModule1WebActionItem6Action(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var
  fs: TFileStream;
begin
  isget := true;
  if Request.MethodType = mtPost then
  begin
    fs := TFileStream.Create(fname, fmCreate);
    try
      bglist.Clear;
      bglist.Add('');
      bglist.Add('(*ユーザー様から報告がありました*)');
      bglist.Add(DateToStr(Now));
      bglist.Add(Request.ContentFields.Values['help']);
      bglist.Add('(*報告ここまで*)');
      bglist.Add('');
      bglist.SaveToStream(fs);
      isget := false;
    finally
      fs.Free;
    end;
  end;
  Response.ContentType := 'text/html;charset=utf-8';
  Response.Content := PageProducer5.Content;
end;

procedure TWebModule1.WebModule1WebActionItem7Action(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var
  dbname: string;
begin
  dbname := Request.QueryFields.Values['db'];
  if FDTable1.Locate('dbname', dbname) then
  begin
    FDTable1.Edit;
    dbname := Request.ContentFields.Values['text'];
    FDTable1.FieldByName('dbname').AsString := dbname;
    FDTable1.Post;
  end;
  Response.SendRedirect('/admin?db=' + TURLEncoding.HTML.Encode(dbname));
end;

procedure TWebModule1.WebModuleBeforeDispatch(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
begin
  if mente and (Request.PathInfo <> '/master') then
  begin
    Response.ContentType := 'text/html;charset=utf-8';
    Response.Content := PageProducer4.Content;
    Handled := true;
  end;
end;

procedure TWebModule1.WebModuleCreate(Sender: TObject);
var
  ini: TIniFile;
begin
  ini := TIniFile.Create('data/setting.ini');
  try
    count := ini.ReadInteger('data', 'count', 10);
    pagecount := ini.ReadInteger('data', 'pagecount', 10);
    mente := ini.ReadBool('data', 'mentenance', false);
  finally
    ini.Free;
  end;
  DataSetTableProducer1.MaxRows := count;
  bglist := TStringList.Create;
  RESTRequest1.Execute;
end;

procedure TWebModule1.WebModuleDestroy(Sender: TObject);
var
  ini: TIniFile;
begin
  ini := TIniFile.Create('data/setting.ini');
  try
    ini.WriteInteger('data', 'count', count);
    ini.WriteInteger('data', 'pagecount', pagecount);
    ini.WriteBool('data', 'mentenance', mente);
  finally
    ini.Free;
  end;
  bglist.Free;
end;

{ TPageSearch }

const
  str = '<span style=background-color:yellow>%s</span>';

var
  bool: Boolean;

function TPageSearch.checkState(var st: integer; word, line: string)
  : TFindState;
begin
  result := fdNone;
  for var id := st to Length(line) do
  begin
    if line[id] <> word[1] then
      Continue;
    FText := FText + Copy(line, st, id - st);
    st := id;
    if Copy(line, id, Length(word)) = word then
    begin
      result := fdNormal;
      bool := true;
      break;
    end
    else if Pos(Copy(line, id, Length(line)), word) > 0 then
      result := fdShort;
  end;
end;

constructor TPageSearch.Create;
begin
  FWordList := TStringList.Create;
  FWordList.QuoteChar := '"';
  FWordList.Delimiter := ' ';
  FList := TStringList.Create;
  FResultLST := TStringList.Create;
end;

destructor TPageSearch.Destroy;
begin
  FWordList.Free;
  FList.Free;
  FResultLST.Free;
  inherited;
end;

procedure TPageSearch.processNormal(var id: integer; word, line: string);
begin
  FText := FText + Format(str, [word]);
  inc(id, Length(word));
end;

procedure TPageSearch.processShort(var id, ln: integer; word: string;
  var line: string);
var
  wrd: string;
  cnt: integer;
  state: TFindState;
begin
  state := fdShort;
  cnt := Length(word);
  wrd := Copy(line, id, Length(word));
  FText := FText + Format(str, [wrd]);
  dec(cnt, Length(wrd));
  while state = fdShort do
  begin
    wrd := Copy(word, Length(wrd) + 1, Length(line));
    FText := FText + #13#10 + Format(str, [wrd]);
    dec(cnt, Length(wrd));
    inc(ln);
    if FList.count = ln then
    begin
      bool := false;
      Exit;
    end;
    line := FList[ln];
    id := 1;
    state := checkState(id, wrd, line);
    inc(id, Length(wrd));
  end;
  bool := cnt = 0;
end;

function TPageSearch.Execute(const Text: string): string;
var
  i, id: integer;
  state: TFindState;
  s: string;
begin
  FList.Text := Text;
  bool := false;
  for var str in WordList do
  begin
    FText := '';
    i := 0;
    id := 1;
    while i < FList.count do
    begin
      s := FList[i];
      state := checkState(id, str, s);
      case state of
        fdShort:
          processShort(id, i, str, s);
        fdNormal:
          processNormal(id, str, s);
        fdNone:
          begin
            FText := FText + Copy(s, id, Length(s)) + #13#10;
            id := 1;
            inc(i);
          end;
      end;
    end;
    FList.Text := FText;
  end;
  if bool then
    result := FList.Text;
end;

end.
